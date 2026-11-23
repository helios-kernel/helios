//! Symmetric peer-to-peer multiplexed RPC framing engine.
//!
//! Built directly on [`crate::wire`]'s `(invocation, path)` frame format,
//! supporting concurrent bidirectional invocations, multi-path `stream<T>`
//! and `future<T>` sub-channels with explicit per-stream credit flow control,
//! caller drop cancellation (root `Frame::Close`), connection-local
//! `Frame::ResourceDrop`, and typed [`WireError`] fault propagation across any
//! `futures_io::AsyncRead + futures_io::AsyncWrite` byte stream on both host
//! (`std`) and `wasm32-wasip3` guest targets.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
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
use crate::wire::{Frame, read_frame, write_frame};

/// Default per-stream item credit window granted to a remote `stream<T>`
/// producer.
pub const DEFAULT_STREAM_CREDIT_WINDOW: u32 = 8;

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
}

impl Default for MuxConfig {
    fn default() -> Self {
        Self {
            stream_credit_window: DEFAULT_STREAM_CREDIT_WINDOW,
            max_inbound_paths: MAX_INBOUND_PATHS,
            max_undelivered_bytes: MAX_UNDELIVERED_BYTES,
        }
    }
}

/// Service handler contract driven by [`drive_mux`].
pub trait MuxDispatcher: Send + Sync + 'static {
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
    ) -> impl Future<Output = Result<(), WireError>> + Send + '_;

    /// Drops a connection-local exported resource when the peer emits
    /// [`Frame::ResourceDrop`].
    fn drop_resource(&self, handle: u32)
    -> impl Future<Output = Result<(), WireError>> + Send + '_;

    /// Releases every remaining connection-scoped resource when the transport
    /// disconnects.
    fn on_disconnect(&self) -> impl Future<Output = ()> + Send + '_;
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
    next_invocation: AtomicU32,
    outbound: Mutex<HashMap<u32, Weak<CallCore>>>,
    /// Keeps `CallCore` alive while pre-buffered outbound streams/futures
    /// (`FutureReader::ready`, `StreamReader::from_vec`) wait for peer credit.
    buffered_keepalive: Mutex<HashMap<(CallSide, u32, u32), Arc<CallCore>>>,
    disconnect_reason: Mutex<Option<String>>,
    progress: Progress,
}

struct QueuedFrame {
    frame: Frame,
    ack: Sender<io::Result<()>>,
}

enum ControlEvent {
    Frame(Frame),
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
struct InboundPathTable {
    chunks: HashMap<Vec<u32>, VecDeque<Bytes>>,
    closed: HashSet<Vec<u32>>,
    credits: HashMap<Vec<u32>, u32>,
    undelivered_bytes: usize,
    error: Option<Fault>,
}

impl InboundPathTable {
    fn admits_path(&self, path: &[u32], max_paths: usize) -> bool {
        if self.chunks.contains_key(path)
            || self.closed.contains(path)
            || self.credits.contains_key(path)
        {
            return true;
        }
        let mut distinct = self.chunks.len();
        for closed in &self.closed {
            if !self.chunks.contains_key(closed) {
                distinct += 1;
            }
        }
        for credited in self.credits.keys() {
            if !self.chunks.contains_key(credited) && !self.closed.contains(credited) {
                distinct += 1;
            }
        }
        distinct < max_paths
    }

    fn fail_wire(&mut self, error: WireError) {
        if self.error.is_none() {
            self.error = Some(Fault::Wire(error));
        }
        self.chunks.clear();
        self.closed.clear();
        self.credits.clear();
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
            if !inbound.admits_path(&path, self.shared.config.max_inbound_paths) {
                let err = WireError::TooManyInboundPaths {
                    invocation: self.invocation,
                    max: self.shared.config.max_inbound_paths,
                };
                inbound.fail_wire(err.clone());
                wire_fault = Some(err);
            } else if path.len() >= 2 {
                let current_bytes = inbound.undelivered_bytes;
                let max_bytes = self.shared.config.max_undelivered_bytes;
                match inbound.credits.get_mut(&path) {
                    Some(credits) if *credits > 0 => {
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
                            inbound.undelivered_bytes += payload.len();
                            inbound.chunks.entry(path).or_default().push_back(payload);
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
                inbound.chunks.entry(path).or_default().push_back(payload);
            }
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
            if inbound.admits_path(&path, self.shared.config.max_inbound_paths) {
                inbound.closed.insert(path);
            } else {
                let err = WireError::TooManyInboundPaths {
                    invocation: self.invocation,
                    max: self.shared.config.max_inbound_paths,
                };
                inbound.fail_wire(err.clone());
                wire_fault = Some(err);
            }
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
    ) -> Result<(), WireError> {
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
            for payload in payloads {
                self.send_control(Frame::Data {
                    invocation: self.invocation,
                    path: out_path.clone(),
                    payload,
                });
            }
            if finished {
                self.send_control(Frame::Close {
                    invocation: self.invocation,
                    path: out_path,
                });
                self.shared.buffered_keepalive.lock().await.remove(&(
                    self.side,
                    self.invocation,
                    sub_id,
                ));
            }
            return Ok(());
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
        Ok(())
    }

    async fn cancel_from_peer(&self) {
        self.cancelled.store(true, Ordering::Release);
        {
            let mut inbound = self.inbound.lock().await;
            if inbound.error.is_none() {
                inbound.error = Some(Fault::Remote("invocation cancelled by caller".to_owned()));
            }
        }
        let slots: Vec<Arc<WriterSlot>> = self.writers.lock().await.values().cloned().collect();
        for slot in slots {
            slot.peer_stopped.store(true, Ordering::Release);
            slot.progress.signal();
        }
        self.progress.signal();
    }

    async fn fail_remote(&self, message: String) {
        {
            let mut inbound = self.inbound.lock().await;
            if inbound.error.is_none() {
                inbound.error = Some(Fault::Remote(message));
            }
        }
        let slots: Vec<Arc<WriterSlot>> = self.writers.lock().await.values().cloned().collect();
        for slot in slots {
            slot.progress.signal();
        }
        self.progress.signal();
    }

    async fn fail_wire(&self, error: WireError) {
        {
            let mut inbound = self.inbound.lock().await;
            inbound.fail_wire(error);
        }
        let slots: Vec<Arc<WriterSlot>> = self.writers.lock().await.values().cloned().collect();
        for slot in slots {
            slot.progress.signal();
        }
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

/// Credit-controlled sub-path writer backing `stream<T>` and `future<T>`.
pub struct SubpathWriter {
    core: Arc<CallCore>,
    sub_id: u32,
    slot: Arc<WriterSlot>,
    closed: bool,
}

impl Drop for SubpathWriter {
    fn drop(&mut self) {
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
    reached_eof: bool,
}

impl Drop for SubpathReader {
    fn drop(&mut self) {
        if !self.reached_eof {
            self.core.send_control(Frame::Close {
                invocation: self.core.invocation,
                path: vec![self.core.side.out_stop_dir(), self.sub_id],
            });
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
        open_reader(&self.core, sub_id, credit_window).await
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

    pub async fn create_subpath_writer(&self) -> (u32, SubpathWriter) {
        create_writer(&self.core).await
    }

    pub fn create_empty_subpath(&self) -> u32 {
        let sub_id = self.core.next_subpath.fetch_add(1, Ordering::Relaxed);
        self.core.send_control(Frame::Close {
            invocation: self.core.invocation,
            path: vec![self.core.side.out_data_dir(), sub_id],
        });
        sub_id
    }

    pub async fn create_ready_future_subpath(&self, payload: Vec<u8>) -> u32 {
        let sub_id = self.core.next_subpath.fetch_add(1, Ordering::Relaxed);
        let mut queue = VecDeque::with_capacity(1);
        queue.push_back(payload);
        self.core
            .prebuffered_streams
            .lock()
            .await
            .insert(sub_id, queue);
        sub_id
    }

    pub async fn open_subpath_reader(
        &self,
        sub_id: u32,
        credit_window: u32,
    ) -> Result<SubpathReader, TransportError> {
        open_reader(&self.core, sub_id, credit_window).await
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

    pub async fn create_subpath_writer(&self) -> (u32, SubpathWriter) {
        create_writer(&self.core).await
    }

    pub fn create_empty_subpath(&self) -> u32 {
        let sub_id = self.core.next_subpath.fetch_add(1, Ordering::Relaxed);
        self.core.send_control(Frame::Close {
            invocation: self.core.invocation,
            path: vec![self.core.side.out_data_dir(), sub_id],
        });
        sub_id
    }

    pub async fn create_ready_future_subpath(&self, payload: Vec<u8>) -> u32 {
        let sub_id = self.core.next_subpath.fetch_add(1, Ordering::Relaxed);
        let mut queue = VecDeque::with_capacity(1);
        queue.push_back(payload);
        self.core
            .prebuffered_streams
            .lock()
            .await
            .insert(sub_id, queue);
        sub_id
    }

    pub async fn open_subpath_reader(
        &self,
        sub_id: u32,
        credit_window: u32,
    ) -> Result<SubpathReader, TransportError> {
        open_reader(&self.core, sub_id, credit_window).await
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
                if let Some(queue) = inbound.chunks.get_mut(&self.path)
                    && let Some(chunk) = queue.pop_front()
                {
                    if queue.is_empty() {
                        inbound.chunks.remove(&self.path);
                    }
                    inbound.undelivered_bytes -= chunk.len();
                    let is_closed = inbound.closed.contains(&self.path);
                    let replenish =
                        if !is_closed && let Some(credits) = inbound.credits.get_mut(&self.path) {
                            *credits = credits.saturating_add(1);
                            true
                        } else {
                            false
                        };
                    Some(Ok(Some((chunk, replenish))))
                } else if inbound.closed.contains(&self.path) {
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
                        self.core.send_control(Frame::Credit {
                            invocation: self.core.invocation,
                            path: self.path.clone(),
                            credits: 1,
                        });
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

async fn create_writer(core: &Arc<CallCore>) -> (u32, SubpathWriter) {
    let sub_id = core.next_subpath.fetch_add(1, Ordering::Relaxed);
    let slot = Arc::new(WriterSlot::new());
    core.writers.lock().await.insert(sub_id, Arc::clone(&slot));
    (
        sub_id,
        SubpathWriter {
            core: Arc::clone(core),
            sub_id,
            slot,
            closed: false,
        },
    )
}

async fn open_reader(
    core: &Arc<CallCore>,
    sub_id: u32,
    credit_window: u32,
) -> Result<SubpathReader, TransportError> {
    let window = credit_window.max(1);
    let path = vec![core.side.in_data_dir(), sub_id];
    {
        let mut inbound = core.inbound.lock().await;
        if !inbound.admits_path(&path, core.shared.config.max_inbound_paths) {
            let err = WireError::TooManyInboundPaths {
                invocation: core.invocation,
                max: core.shared.config.max_inbound_paths,
            };
            inbound.fail_wire(err.clone());
            return Err(TransportError::Wire(err));
        }
        inbound.credits.insert(path.clone(), window);
    }
    core.send_control(Frame::Credit {
        invocation: core.invocation,
        path: path.clone(),
        credits: window,
    });
    Ok(SubpathReader {
        core: Arc::clone(core),
        sub_id,
        path,
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
            if let Some(queue) = inbound.chunks.get_mut(&path) {
                let mut drained = Vec::new();
                let mut released = 0usize;
                while let Some(chunk) = queue.pop_front() {
                    released += chunk.len();
                    drained.extend_from_slice(&chunk);
                }
                inbound.chunks.remove(&path);
                inbound.undelivered_bytes -= released;
                let done = inbound.closed.contains(&path);
                Some(Ok((drained, done)))
            } else if inbound.closed.contains(&path) {
                Some(Ok((Vec::new(), true)))
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

    pub fn stream_credit_window(&self) -> u32 {
        self.state.config.stream_credit_window
    }

    pub fn close(&self) {
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
            return Err(TransportError::Closed);
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
                return Err(TransportError::Closed);
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
    let (outgoing_tx, outgoing_rx) = async_channel::bounded(8);
    let (control_tx, control_rx) = async_channel::unbounded();
    let shared = Arc::new(MuxShared {
        config,
        closed: AtomicBool::new(false),
        next_invocation: AtomicU32::new(1),
        outbound: Mutex::new(HashMap::new()),
        buffered_keepalive: Mutex::new(HashMap::new()),
        disconnect_reason: Mutex::new(None),
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

    let mut read_fut = Box::pin(read_next_frame_owned(read));
    let mut writer_slot = Some(write);
    let mut write_fut = None;
    let mut shutdown_requested = false;
    let mut control_rx = std::pin::pin!(control_rx);
    let mut outgoing_rx = std::pin::pin!(outgoing_rx);

    let loop_outcome: Result<(), TransportError> = async {
        enum Step<R> {
            FrameRead(R, io::Result<Option<Frame>>),
            Control(ControlEvent),
            Outgoing(QueuedFrame),
            ServerDone(Option<(u32, WireError)>),
            WriteDone,
        }

        loop {
            while let Ok(ctrl) = control_rx.try_recv() {
                match ctrl {
                    ControlEvent::Frame(frame) => priority_outbox.push_back((frame, None)),
                    ControlEvent::Shutdown => {
                        shutdown_requested = true;
                        break;
                    }
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

            let step = std::future::poll_fn(|cx| {
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

                if !shutdown_requested
                    && let Poll::Ready((r, frame_res)) = read_fut.as_mut().poll(cx)
                {
                    return Poll::Ready(Ok(Step::FrameRead(r, frame_res)));
                }

                if !shutdown_requested {
                    if let Poll::Ready(Some(ctrl)) =
                        futures_core::Stream::poll_next(control_rx.as_mut(), cx)
                    {
                        return Poll::Ready(Ok(Step::Control(ctrl)));
                    }
                    if write_fut.is_none()
                        && let Poll::Ready(Some(queued)) =
                            futures_core::Stream::poll_next(outgoing_rx.as_mut(), cx)
                    {
                        return Poll::Ready(Ok(Step::Outgoing(queued)));
                    }
                }

                Poll::Pending
            })
            .await?;

            match step {
                Step::WriteDone => {}
                Step::Control(ControlEvent::Frame(frame)) => {
                    priority_outbox.push_back((frame, None));
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
                    read_fut = Box::pin(read_next_frame_owned(reader_back));
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
        call.fail_remote(reason.clone()).await;
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
) -> (R, io::Result<Option<Frame>>) {
    let res = read_frame(&mut read).await;
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
            let mark = core.progress.mark();
            if core.cancelled.load(Ordering::Acquire) || core.shared.closed.load(Ordering::Acquire)
            {
                return;
            }
            core.progress.changed(mark).await;
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
                    if let Some(core) = resolve_outbound(shared, invocation).await {
                        let _ = core.grant_credit(path, sub_id, credits).await;
                    }
                }
                DIR_CALLEE_TO_CALLER => {
                    if let Some(core) = resolve_inbound(inbound_calls, invocation)
                        && let Err(wire_err) = core.grant_credit(path, sub_id, credits).await
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
