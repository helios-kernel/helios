use std::collections::VecDeque;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Poll;

use async_lock::Mutex;
use event_listener::{Event, EventListener};
use helios_inspector_protocol::WireError;
use helios_inspector_protocol::mux::{
    CallHandle, InboundCall, MaybeSend, OutboundCall, PeerHandle, SubpathReader, SubpathStopWatch,
    SubpathWriter,
};

use crate::error::RpcError;
use crate::resource::{RemoteResource, ResourceEntry, ResourceTable, ResourceTableInner};
use crate::stream::{FutureReader, StreamReader};

#[cfg(not(target_arch = "wasm32"))]
pub(crate) type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
#[cfg(target_arch = "wasm32")]
pub(crate) type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

pub(crate) type SubpathTask = BoxFuture<'static, ()>;

/// Handle for queuing connection-scoped subpath pump tasks onto [`crate::Endpoint::drive`].
#[doc(hidden)]
#[derive(Clone)]
pub struct SubpathSpawner {
    tx: async_channel::Sender<SubpathTask>,
}

impl SubpathSpawner {
    pub(crate) fn new() -> (Self, async_channel::Receiver<SubpathTask>) {
        let (tx, rx) = async_channel::unbounded();
        (Self { tx }, rx)
    }

    pub(crate) fn spawn(&self, fut: impl Future<Output = ()> + MaybeSend + 'static) {
        let _ = self.tx.try_send(Box::pin(fut));
    }
}

/// Cancellation signal shared between an enclosing send's rollback guard and
/// any spawned pre-buffered subpath pump tasks it activated.
pub(crate) struct SubpathCancelToken {
    cancelled: AtomicBool,
    event: Event,
}

impl SubpathCancelToken {
    pub(crate) fn new() -> Self {
        Self {
            cancelled: AtomicBool::new(false),
            event: Event::new(),
        }
    }

    pub(crate) fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.event.notify(usize::MAX);
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    pub(crate) async fn wait(&self) {
        let mut listener: Option<EventListener> = None;
        std::future::poll_fn(|cx| {
            loop {
                if self.cancelled.load(Ordering::Acquire) {
                    return Poll::Ready(());
                }
                if listener.is_none() {
                    listener = Some(self.event.listen());
                    continue;
                }
                let active = listener
                    .as_mut()
                    .expect("subpath cancel listener must exist while parked");
                match Pin::new(active).poll(cx) {
                    Poll::Ready(()) => {
                        listener = None;
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }
        })
        .await;
    }
}

/// Type-erased rollback hook into a connection's [`ResourceTable`].
#[cfg(not(target_arch = "wasm32"))]
pub(crate) trait TableRollback: Send + Sync + 'static {
    fn rollback_async(&self, handles: Vec<u32>) -> BoxFuture<'_, ()>;
    fn rollback_sync(&self, handles: Vec<u32>);
}

#[cfg(target_arch = "wasm32")]
pub(crate) trait TableRollback: 'static {
    fn rollback_async(&self, handles: Vec<u32>) -> BoxFuture<'_, ()>;
    fn rollback_sync(&self, handles: Vec<u32>);
}

impl<R: ResourceEntry> TableRollback for ResourceTable<R> {
    fn rollback_async(&self, handles: Vec<u32>) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            self.rollback_handles(&handles).await;
        })
    }

    fn rollback_sync(&self, handles: Vec<u32>) {
        self.rollback_handles_sync(handles);
    }
}

pub(crate) fn rollback_remote_handles(handles: Vec<(PeerHandle, u32)>) {
    for (peer, handle) in handles {
        peer.drop_remote_resource(handle);
    }
}

/// Newly exported server handles and transferred client handles captured during
/// an encoding pass so failed or cancelled transmission can release them cleanly.
#[derive(Default)]
pub(crate) struct EncodedHandlesRollback {
    table: Option<Arc<dyn TableRollback>>,
    inserted_handles: Vec<u32>,
    remote_handles: Vec<(PeerHandle, u32)>,
}

impl EncodedHandlesRollback {
    pub(crate) fn remote_only(remote_handles: Vec<(PeerHandle, u32)>) -> Self {
        Self {
            table: None,
            inserted_handles: Vec::new(),
            remote_handles,
        }
    }

    pub(crate) fn with_table(
        table: Arc<dyn TableRollback>,
        inserted_handles: Vec<u32>,
        remote_handles: Vec<(PeerHandle, u32)>,
    ) -> Self {
        Self {
            table: Some(table),
            inserted_handles,
            remote_handles,
        }
    }
}

/// RAII rollback guard protecting in-flight frame transmission (root requests,
/// root responses, `StreamWriter::send_batch`, `FutureWriter::resolve`, and
/// server-side pre-buffered pump tasks).
///
/// Disarming after `send(...).await` succeeds commits handle ownership to the
/// wire; dropping while still armed rolls back every handle synchronously and
/// cancels any nested spawned subpath pumps.
pub(crate) struct SendRollbackGuard {
    table: Option<Arc<dyn TableRollback>>,
    inserted_handles: Vec<u32>,
    remote_handles: Vec<(PeerHandle, u32)>,
    subpath_cancels: Vec<Arc<SubpathCancelToken>>,
}

impl SendRollbackGuard {
    pub(crate) fn new(rollback: EncodedHandlesRollback) -> Self {
        Self {
            table: rollback.table,
            inserted_handles: rollback.inserted_handles,
            remote_handles: rollback.remote_handles,
            subpath_cancels: Vec::new(),
        }
    }

    pub(crate) fn add_cancels(&mut self, cancels: Vec<Arc<SubpathCancelToken>>) {
        self.subpath_cancels.extend(cancels);
    }

    pub(crate) fn disarm(&mut self) {
        self.inserted_handles.clear();
        self.remote_handles.clear();
        self.subpath_cancels.clear();
    }

    pub(crate) async fn rollback_now(mut self) {
        let cancels = std::mem::take(&mut self.subpath_cancels);
        for token in cancels {
            token.cancel();
        }
        let inserted = std::mem::take(&mut self.inserted_handles);
        let remote = std::mem::take(&mut self.remote_handles);
        if !inserted.is_empty()
            && let Some(table) = self.table.take()
        {
            table.rollback_async(inserted).await;
        }
        rollback_remote_handles(remote);
    }
}

impl Drop for SendRollbackGuard {
    fn drop(&mut self) {
        for token in std::mem::take(&mut self.subpath_cancels) {
            token.cancel();
        }
        let inserted = std::mem::take(&mut self.inserted_handles);
        if !inserted.is_empty()
            && let Some(table) = self.table.as_ref()
        {
            table.rollback_sync(inserted);
        }
        rollback_remote_handles(std::mem::take(&mut self.remote_handles));
    }
}

/// Encoded sub-path payload ready for transmission alongside nested sub-paths
/// and rollback state.
pub(crate) struct EncodedOutboundFrame {
    pub(crate) bytes: Vec<u8>,
    pub(crate) subpaths: Vec<PendingOutboundSubpath>,
    pub(crate) rollback: EncodedHandlesRollback,
}

/// Result of encoding a stream batch or future value: synchronous on the
/// zero-lock fast path and async only when locking a server [`ResourceTable`].
pub(crate) enum EncodeResult {
    Ready(Result<EncodedOutboundFrame, WireError>),
    Pending(BoxFuture<'static, Result<EncodedOutboundFrame, WireError>>),
}

impl EncodeResult {
    pub(crate) async fn resolve(self) -> Result<EncodedOutboundFrame, WireError> {
        match self {
            Self::Ready(res) => res,
            Self::Pending(fut) => fut.await,
        }
    }
}

/// Connection-bound encoder installed on an [`OutboundPipe`] when its reader
/// half crosses an invocation boundary.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) trait OutboundEncoder<T>: Send + Sync + 'static {
    fn encode_batch(&self, call: &CallHandle, items: Vec<T>) -> EncodeResult;
    fn encode_one(&self, call: &CallHandle, item: T) -> EncodeResult;
}

#[cfg(target_arch = "wasm32")]
pub(crate) trait OutboundEncoder<T>: 'static {
    fn encode_batch(&self, call: &CallHandle, items: Vec<T>) -> EncodeResult;
    fn encode_one(&self, call: &CallHandle, item: T) -> EncodeResult;
}

pub(crate) struct TableOutboundEncoder<T, R: ResourceEntry> {
    resources: Option<ResourceTable<R>>,
    spawner: Option<SubpathSpawner>,
    _marker: PhantomData<fn(T)>,
}

// `PhantomData<fn(T)>` is unconditionally `Send + Sync`, and `ResourceTable<R>`
// / `SubpathSpawner` are `MaybeSend + MaybeSync`.
impl<T, R: ResourceEntry> TableOutboundEncoder<T, R> {
    pub(crate) fn new(
        resources: Option<ResourceTable<R>>,
        spawner: Option<SubpathSpawner>,
    ) -> Self {
        Self {
            resources,
            spawner,
            _marker: PhantomData,
        }
    }
}

impl<T, R> OutboundEncoder<T> for TableOutboundEncoder<T, R>
where
    R: ResourceEntry,
    T: RpcEncode<R> + MaybeSend + 'static,
{
    fn encode_batch(&self, call: &CallHandle, items: Vec<T>) -> EncodeResult {
        if T::CONTAINS_RESOURCES
            && let Some(resources) = self.resources.clone()
        {
            let call = call.clone();
            let spawner = self.spawner.clone();
            return EncodeResult::Pending(Box::pin(async move {
                encode_with_table::<R>(&call, &resources, spawner.as_ref(), |enc| {
                    T::rpc_encode_vec(items, enc)
                })
                .await
            }));
        }
        EncodeResult::Ready(encode_without_table::<R>(
            call,
            self.resources.as_ref(),
            self.spawner.as_ref(),
            |enc| T::rpc_encode_vec(items, enc),
        ))
    }

    fn encode_one(&self, call: &CallHandle, item: T) -> EncodeResult {
        if T::CONTAINS_RESOURCES
            && let Some(resources) = self.resources.clone()
        {
            let call = call.clone();
            let spawner = self.spawner.clone();
            return EncodeResult::Pending(Box::pin(async move {
                encode_with_table::<R>(&call, &resources, spawner.as_ref(), |enc| {
                    item.rpc_encode(enc)
                })
                .await
            }));
        }
        EncodeResult::Ready(encode_without_table::<R>(
            call,
            self.resources.as_ref(),
            self.spawner.as_ref(),
            |enc| item.rpc_encode(enc),
        ))
    }
}

fn encode_without_table<R: ResourceEntry>(
    call: &CallHandle,
    resource_table: Option<&ResourceTable<R>>,
    spawner: Option<&SubpathSpawner>,
    write: impl FnOnce(&mut Encoder<'_, R>) -> Result<(), WireError>,
) -> Result<EncodedOutboundFrame, WireError> {
    let mut enc = Encoder::<R>::with_context(Some(call), None, resource_table, spawner);
    if let Err(err) = write(&mut enc) {
        rollback_remote_handles(enc.take_transferred_remote_handles());
        return Err(err);
    }
    let finished = enc.finish_full();
    Ok(EncodedOutboundFrame {
        bytes: finished.bytes,
        subpaths: finished.subpaths,
        rollback: EncodedHandlesRollback::remote_only(finished.remote_handles),
    })
}

async fn encode_with_table<R: ResourceEntry>(
    call: &CallHandle,
    resources: &ResourceTable<R>,
    spawner: Option<&SubpathSpawner>,
    write: impl FnOnce(&mut Encoder<'_, R>) -> Result<(), WireError>,
) -> Result<EncodedOutboundFrame, WireError> {
    let outcome = {
        let mut table = resources.lock().await;
        let mut enc =
            Encoder::with_context(Some(call), Some(&mut *table), Some(resources), spawner);
        match write(&mut enc) {
            Ok(()) => {
                let finished = enc.finish_full();
                Ok(EncodedOutboundFrame {
                    bytes: finished.bytes,
                    subpaths: finished.subpaths,
                    rollback: EncodedHandlesRollback::with_table(
                        Arc::new(resources.clone()),
                        finished.inserted_handles,
                        finished.remote_handles,
                    ),
                })
            }
            Err(err) => {
                let inserted = enc.take_inserted_handles();
                let remote = enc.take_transferred_remote_handles();
                drop(enc);
                let mut rolled_back = Vec::with_capacity(inserted.len());
                for id in inserted {
                    if let Some(entry) = table.remove_unconditional(id) {
                        rolled_back.push(entry);
                    }
                }
                Err((err, rolled_back, remote))
            }
        }
    };
    match outcome {
        Ok(frame) => Ok(frame),
        Err((err, rolled_back, remote)) => {
            drop(rolled_back);
            rollback_remote_handles(remote);
            Err(err)
        }
    }
}

pub(crate) struct MappedOutboundEncoder<T, U> {
    inner: Arc<dyn OutboundEncoder<U>>,
    map: fn(T) -> U,
}

impl<T, U> MappedOutboundEncoder<T, U> {
    pub(crate) fn new(inner: Arc<dyn OutboundEncoder<U>>, map: fn(T) -> U) -> Self {
        Self { inner, map }
    }
}

impl<T: MaybeSend + 'static, U: MaybeSend + 'static> OutboundEncoder<T>
    for MappedOutboundEncoder<T, U>
{
    fn encode_batch(&self, call: &CallHandle, items: Vec<T>) -> EncodeResult {
        let mapped: Vec<U> = items.into_iter().map(self.map).collect();
        self.inner.encode_batch(call, mapped)
    }

    fn encode_one(&self, call: &CallHandle, item: T) -> EncodeResult {
        self.inner.encode_one(call, (self.map)(item))
    }
}

/// Type-erased binder stored inside [`crate::StreamReader`] / [`crate::FutureReader`]
/// after `__map_outbound` so the original [`OutboundPipe`] can be bound with a
/// mapped connection-scoped encoder when encoded on the server.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) trait OutboundSlot<U>: Send + 'static {
    fn bind_with(
        self: Box<Self>,
        writer: SubpathWriter,
        encoder: Arc<dyn OutboundEncoder<U>>,
    ) -> BoxFuture<'static, ()>;
}

#[cfg(target_arch = "wasm32")]
pub(crate) trait OutboundSlot<U>: 'static {
    fn bind_with(
        self: Box<Self>,
        writer: SubpathWriter,
        encoder: Arc<dyn OutboundEncoder<U>>,
    ) -> BoxFuture<'static, ()>;
}

pub(crate) struct MappedOutboundSlot<T, U> {
    inner: Box<dyn OutboundSlot<T>>,
    map: fn(T) -> U,
}

impl<T, U> MappedOutboundSlot<T, U> {
    pub(crate) fn new(inner: Box<dyn OutboundSlot<T>>, map: fn(T) -> U) -> Self {
        Self { inner, map }
    }
}

impl<T: MaybeSend + 'static, U: MaybeSend + 'static> OutboundSlot<U> for MappedOutboundSlot<T, U> {
    fn bind_with(
        self: Box<Self>,
        writer: SubpathWriter,
        encoder: Arc<dyn OutboundEncoder<U>>,
    ) -> BoxFuture<'static, ()> {
        let mapped = Arc::new(MappedOutboundEncoder::new(encoder, self.map));
        self.inner.bind_with(writer, mapped)
    }
}

pub(crate) struct PipeOutboundSlot<T> {
    pipe: Arc<OutboundPipe<T>>,
}

impl<T> PipeOutboundSlot<T> {
    pub(crate) fn new(pipe: Arc<OutboundPipe<T>>) -> Self {
        Self { pipe }
    }
}

impl<T: MaybeSend + 'static> OutboundSlot<T> for PipeOutboundSlot<T> {
    fn bind_with(
        self: Box<Self>,
        writer: SubpathWriter,
        encoder: Arc<dyn OutboundEncoder<T>>,
    ) -> BoxFuture<'static, ()> {
        let pipe = self.pipe;
        Box::pin(async move {
            pipe.bind(writer, encoder).await;
        })
    }
}

/// Deferred binder stored in [`PendingOutboundSubpath::Live`].
#[cfg(not(target_arch = "wasm32"))]
pub(crate) trait PendingOutboundBind: Send + 'static {
    fn bind(self: Box<Self>, writer: SubpathWriter) -> BoxFuture<'static, ()>;
}

#[cfg(target_arch = "wasm32")]
pub(crate) trait PendingOutboundBind: 'static {
    fn bind(self: Box<Self>, writer: SubpathWriter) -> BoxFuture<'static, ()>;
}

pub(crate) struct BoundSlotBinder<T> {
    slot: Box<dyn OutboundSlot<T>>,
    encoder: Arc<dyn OutboundEncoder<T>>,
}

impl<T> BoundSlotBinder<T> {
    pub(crate) fn new(
        slot: Box<dyn OutboundSlot<T>>,
        encoder: Arc<dyn OutboundEncoder<T>>,
    ) -> Self {
        Self { slot, encoder }
    }
}

impl<T: MaybeSend + 'static> PendingOutboundBind for BoundSlotBinder<T> {
    fn bind(self: Box<Self>, writer: SubpathWriter) -> BoxFuture<'static, ()> {
        self.slot.bind_with(writer, self.encoder)
    }
}

pub(crate) struct DirectPipeBinder<T> {
    pipe: Arc<OutboundPipe<T>>,
    encoder: Arc<dyn OutboundEncoder<T>>,
}

impl<T> DirectPipeBinder<T> {
    pub(crate) fn new(pipe: Arc<OutboundPipe<T>>, encoder: Arc<dyn OutboundEncoder<T>>) -> Self {
        Self { pipe, encoder }
    }
}

impl<T: MaybeSend + 'static> PendingOutboundBind for DirectPipeBinder<T> {
    fn bind(self: Box<Self>, writer: SubpathWriter) -> BoxFuture<'static, ()> {
        let pipe = self.pipe;
        let encoder = self.encoder;
        Box::pin(async move {
            pipe.bind(writer, encoder).await;
        })
    }
}

/// Deferred pump factory stored in [`PendingOutboundSubpath::Pumped`] for
/// resource-carrying `StreamReader::from_vec` / `FutureReader::ready` payloads.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) trait PendingOutboundPump: Send + 'static {
    fn into_task(
        self: Box<Self>,
        writer: SubpathWriter,
        cancel: Arc<SubpathCancelToken>,
    ) -> SubpathTask;
}

#[cfg(target_arch = "wasm32")]
pub(crate) trait PendingOutboundPump: 'static {
    fn into_task(
        self: Box<Self>,
        writer: SubpathWriter,
        cancel: Arc<SubpathCancelToken>,
    ) -> SubpathTask;
}

/// Result of decoding a stream batch or future value: synchronous on the
/// zero-lock fast path and async only when locking a server [`ResourceTable`].
pub(crate) enum DecodeResult<T> {
    Ready(Result<(T, Vec<PendingInboundSubpath>), WireError>),
    Pending(BoxFuture<'static, Result<(T, Vec<PendingInboundSubpath>), WireError>>),
}

impl<T> DecodeResult<T> {
    pub(crate) async fn resolve(self) -> Result<(T, Vec<PendingInboundSubpath>), WireError> {
        match self {
            Self::Ready(res) => res,
            Self::Pending(fut) => fut.await,
        }
    }
}

/// Connection-bound decoder carried by inbound [`crate::StreamReader`] and
/// [`crate::FutureReader`] handles.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) trait InboundDecoder<T>: Send + Sync + 'static {
    fn decode_batch(&self, bytes: &[u8], peer: PeerHandle) -> DecodeResult<Vec<T>>;
    fn decode_one(&self, bytes: &[u8], peer: PeerHandle) -> DecodeResult<T>;
}

#[cfg(target_arch = "wasm32")]
pub(crate) trait InboundDecoder<T>: 'static {
    fn decode_batch(&self, bytes: &[u8], peer: PeerHandle) -> DecodeResult<Vec<T>>;
    fn decode_one(&self, bytes: &[u8], peer: PeerHandle) -> DecodeResult<T>;
}

pub(crate) struct TableInboundDecoder<T, R: ResourceEntry> {
    resources: Option<ResourceTable<R>>,
    spawner: Option<SubpathSpawner>,
    _marker: PhantomData<fn() -> T>,
}

impl<T, R: ResourceEntry> TableInboundDecoder<T, R> {
    pub(crate) fn new(
        resources: Option<ResourceTable<R>>,
        spawner: Option<SubpathSpawner>,
    ) -> Self {
        Self {
            resources,
            spawner,
            _marker: PhantomData,
        }
    }
}

impl<T, R> InboundDecoder<T> for TableInboundDecoder<T, R>
where
    R: ResourceEntry,
    T: RpcDecode<R> + MaybeSend + 'static,
{
    fn decode_batch(&self, bytes: &[u8], peer: PeerHandle) -> DecodeResult<Vec<T>> {
        if T::CONTAINS_RESOURCES
            && let Some(resources) = self.resources.clone()
        {
            let owned = bytes.to_vec();
            let spawner = self.spawner.clone();
            return DecodeResult::Pending(Box::pin(async move {
                let outcome = {
                    let mut table = resources.lock().await;
                    let mut dec = Decoder::with_context(
                        &owned,
                        peer,
                        Some(&mut *table),
                        Some(&resources),
                        spawner.as_ref(),
                    );
                    match T::rpc_decode_vec(&mut dec) {
                        Ok(batch) => match dec.finish() {
                            Ok(subpaths) => Ok((batch, subpaths)),
                            Err(err) => Err((err, Some(batch))),
                        },
                        Err(err) => Err((err, None)),
                    }
                };
                match outcome {
                    Ok(ok) => Ok(ok),
                    Err((err, dropped)) => {
                        drop(dropped);
                        Err(err)
                    }
                }
            }));
        }
        let mut dec = Decoder::<R>::with_context(
            bytes,
            peer,
            None,
            self.resources.as_ref(),
            self.spawner.as_ref(),
        );
        DecodeResult::Ready((|| {
            let batch = T::rpc_decode_vec(&mut dec)?;
            let subpaths = dec.finish()?;
            Ok((batch, subpaths))
        })())
    }

    fn decode_one(&self, bytes: &[u8], peer: PeerHandle) -> DecodeResult<T> {
        if T::CONTAINS_RESOURCES
            && let Some(resources) = self.resources.clone()
        {
            let owned = bytes.to_vec();
            let spawner = self.spawner.clone();
            return DecodeResult::Pending(Box::pin(async move {
                let outcome = {
                    let mut table = resources.lock().await;
                    let mut dec = Decoder::with_context(
                        &owned,
                        peer,
                        Some(&mut *table),
                        Some(&resources),
                        spawner.as_ref(),
                    );
                    match T::rpc_decode(&mut dec) {
                        Ok(value) => match dec.finish() {
                            Ok(subpaths) => Ok((value, subpaths)),
                            Err(err) => Err((err, Some(value))),
                        },
                        Err(err) => Err((err, None)),
                    }
                };
                match outcome {
                    Ok(ok) => Ok(ok),
                    Err((err, dropped)) => {
                        drop(dropped);
                        Err(err)
                    }
                }
            }));
        }
        let mut dec = Decoder::<R>::with_context(
            bytes,
            peer,
            None,
            self.resources.as_ref(),
            self.spawner.as_ref(),
        );
        DecodeResult::Ready((|| {
            let value = T::rpc_decode(&mut dec)?;
            let subpaths = dec.finish()?;
            Ok((value, subpaths))
        })())
    }
}

pub(crate) struct MappedInboundDecoder<W, T> {
    inner: Arc<dyn InboundDecoder<W>>,
    map: fn(W) -> T,
}

impl<W, T> MappedInboundDecoder<W, T> {
    pub(crate) fn new(inner: Arc<dyn InboundDecoder<W>>, map: fn(W) -> T) -> Self {
        Self { inner, map }
    }
}

impl<W: MaybeSend + 'static, T: MaybeSend + 'static> InboundDecoder<T>
    for MappedInboundDecoder<W, T>
{
    fn decode_batch(&self, bytes: &[u8], peer: PeerHandle) -> DecodeResult<Vec<T>> {
        let map = self.map;
        match self.inner.decode_batch(bytes, peer) {
            DecodeResult::Ready(res) => DecodeResult::Ready(
                res.map(|(batch, subpaths)| (batch.into_iter().map(map).collect(), subpaths)),
            ),
            DecodeResult::Pending(fut) => DecodeResult::Pending(Box::pin(async move {
                let (batch, subpaths) = fut.await?;
                Ok((batch.into_iter().map(map).collect(), subpaths))
            })),
        }
    }

    fn decode_one(&self, bytes: &[u8], peer: PeerHandle) -> DecodeResult<T> {
        let map = self.map;
        match self.inner.decode_one(bytes, peer) {
            DecodeResult::Ready(res) => {
                DecodeResult::Ready(res.map(|(value, subpaths)| (map(value), subpaths)))
            }
            DecodeResult::Pending(fut) => DecodeResult::Pending(Box::pin(async move {
                let (value, subpaths) = fut.await?;
                Ok((map(value), subpaths))
            })),
        }
    }
}

/// WIT 0.3 `error-context` payload carried over RPC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorContext {
    pub debug_message: String,
}

struct OutboundPipeState<T> {
    writer: Option<SubpathWriter>,
    encoder: Option<Arc<dyn OutboundEncoder<T>>>,
    stop_watch: Option<SubpathStopWatch>,
}

/// Non-generic reader-drop signal shared between an [`OutboundPipe`] and any
/// mapped [`crate::StreamReader`] / [`crate::FutureReader`] so `Drop` can wake
/// the writer without requiring `T: 'static`.
pub(crate) struct OutboundPipeNotify {
    reader_dropped: AtomicBool,
    event: Event,
}

impl OutboundPipeNotify {
    fn new() -> Self {
        Self {
            reader_dropped: AtomicBool::new(false),
            event: Event::new(),
        }
    }

    pub(crate) fn mark_reader_dropped(&self) {
        self.reader_dropped.store(true, Ordering::Release);
        self.event.notify(usize::MAX);
    }
}

/// Shared pipe connecting a [`crate::StreamWriter`] or [`crate::FutureWriter`]
/// to the wire sub-path and connection-scoped encoder allocated when its reader
/// half is encoded onto an invocation.
///
/// The internal lock is only ever held for non-yielding handoff mutations and
/// never across an `.await` point.
pub struct OutboundPipe<T> {
    state: Mutex<OutboundPipeState<T>>,
    bound: AtomicBool,
    writer_dropped: AtomicBool,
    notify: Arc<OutboundPipeNotify>,
}

impl<T> Default for OutboundPipe<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> OutboundPipe<T> {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(OutboundPipeState {
                writer: None,
                encoder: None,
                stop_watch: None,
            }),
            bound: AtomicBool::new(false),
            writer_dropped: AtomicBool::new(false),
            notify: Arc::new(OutboundPipeNotify::new()),
        }
    }

    pub(crate) fn drop_notify(&self) -> Arc<OutboundPipeNotify> {
        Arc::clone(&self.notify)
    }

    pub(crate) async fn bind(&self, writer: SubpathWriter, encoder: Arc<dyn OutboundEncoder<T>>) {
        let mut close_now = None;
        {
            let mut state = self.state.lock().await;
            if self.writer_dropped.load(Ordering::SeqCst) {
                close_now = Some(writer);
            } else {
                state.stop_watch = Some(writer.stop_watch());
                state.writer = Some(writer);
                state.encoder = Some(encoder);
            }
        }
        if let Some(writer) = close_now {
            let _ = writer.close().await;
            return;
        }
        self.bound.store(true, Ordering::SeqCst);
        self.notify.event.notify(usize::MAX);

        // Re-check `writer_dropped` with `SeqCst` after unlocking so a
        // concurrent synchronous `Drop` (`mark_writer_dropped`) whose
        // `try_lock()` lost the race cannot leave an orphaned `SubpathWriter`.
        if self.writer_dropped.load(Ordering::SeqCst) {
            let orphaned = {
                let mut state = self.state.lock().await;
                state.encoder = None;
                state.writer.take()
            };
            if let Some(writer) = orphaned {
                let _ = writer.close().await;
            }
        }
    }

    pub(crate) fn mark_writer_dropped(&self) {
        self.writer_dropped.store(true, Ordering::SeqCst);
        if let Some(mut state) = self.state.try_lock() {
            // Dropping `SubpathWriter` enqueues `Frame::Close` on the wire.
            let _ = state.writer.take();
            state.encoder = None;
        }
        self.notify.event.notify(usize::MAX);
    }

    pub(crate) fn mark_reader_dropped(&self) {
        self.notify.mark_reader_dropped();
    }

    pub(crate) fn is_closed_for_writer(&self) -> bool {
        self.notify.reader_dropped.load(Ordering::Acquire)
    }

    pub(crate) async fn wait_until_bound(&self) -> Result<(), RpcError> {
        let mut listener: Option<EventListener> = None;
        std::future::poll_fn(|cx| {
            loop {
                if self.notify.reader_dropped.load(Ordering::Acquire) {
                    return Poll::Ready(Err(RpcError::StreamClosed));
                }
                if self.bound.load(Ordering::Acquire) {
                    return Poll::Ready(Ok(()));
                }
                if listener.is_none() {
                    listener = Some(self.notify.event.listen());
                    continue;
                }
                let active = listener
                    .as_mut()
                    .expect("outbound pipe listener must exist while parked");
                match Pin::new(active).poll(cx) {
                    Poll::Ready(()) => {
                        listener = None;
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }
        })
        .await
    }

    pub(crate) async fn take_bound(&self) -> Option<(SubpathWriter, Arc<dyn OutboundEncoder<T>>)> {
        let mut state = self.state.lock().await;
        let writer = state.writer.take()?;
        let encoder = state.encoder.take()?;
        Some((writer, encoder))
    }

    pub(crate) async fn take_writer_only(&self) -> Option<SubpathWriter> {
        let mut state = self.state.lock().await;
        state.encoder = None;
        state.writer.take()
    }

    pub(crate) async fn stop_watch(&self) -> Option<SubpathStopWatch> {
        self.state.lock().await.stop_watch.clone()
    }

    pub(crate) async fn is_peer_stopped(&self) -> bool {
        self.state
            .lock()
            .await
            .stop_watch
            .as_ref()
            .is_some_and(SubpathStopWatch::is_peer_stopped)
    }
}

/// Shared non-generic pipe receiving the [`SubpathReader`] opened when a
/// [`StreamReader`] or [`FutureReader`] is decoded from an incoming payload.
pub struct InboundPipe {
    reader: Mutex<Option<SubpathReader>>,
}

impl Default for InboundPipe {
    fn default() -> Self {
        Self::new()
    }
}

impl InboundPipe {
    pub fn new() -> Self {
        Self {
            reader: Mutex::new(None),
        }
    }

    pub(crate) async fn install(&self, reader: SubpathReader) {
        *self.reader.lock().await = Some(reader);
    }

    pub(crate) async fn take_reader(&self) -> Option<SubpathReader> {
        self.reader.lock().await.take()
    }
}

/// Credit policy for an inbound sub-path opened during decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubpathCreditMode {
    /// Multi-item `stream<T>` with initial window and per-chunk replenishment.
    Streaming { window: u32 },
    /// Single-shot `future<T>` granting 1 credit with no replenishment.
    Oneshot,
}

/// Deferred outbound sub-path registration collected during synchronous
/// encoding and activated before the enclosing frame is transmitted.
pub struct PendingOutboundSubpath(pub(crate) PendingOutboundSubpathKind);

pub(crate) enum PendingOutboundSubpathKind {
    Live {
        sub_id: u32,
        bind: Box<dyn PendingOutboundBind>,
    },
    Buffered {
        sub_id: u32,
        frames: VecDeque<Vec<u8>>,
    },
    Pumped {
        sub_id: u32,
        spawner: SubpathSpawner,
        cancel: Arc<SubpathCancelToken>,
        pump: Box<dyn PendingOutboundPump>,
    },
    Empty {
        sub_id: u32,
    },
}

impl PendingOutboundSubpath {
    pub(crate) fn live(sub_id: u32, bind: Box<dyn PendingOutboundBind>) -> Self {
        Self(PendingOutboundSubpathKind::Live { sub_id, bind })
    }

    pub(crate) fn buffered(sub_id: u32, frames: VecDeque<Vec<u8>>) -> Self {
        Self(PendingOutboundSubpathKind::Buffered { sub_id, frames })
    }

    pub(crate) fn pumped(
        sub_id: u32,
        spawner: SubpathSpawner,
        cancel: Arc<SubpathCancelToken>,
        pump: Box<dyn PendingOutboundPump>,
    ) -> Self {
        Self(PendingOutboundSubpathKind::Pumped {
            sub_id,
            spawner,
            cancel,
            pump,
        })
    }

    pub(crate) fn empty(sub_id: u32) -> Self {
        Self(PendingOutboundSubpathKind::Empty { sub_id })
    }
}

/// Deferred inbound sub-path registration collected during synchronous
/// decoding and activated before returning decoded values to caller/handler.
pub struct PendingInboundSubpath {
    pub sub_id: u32,
    pub credit_mode: SubpathCreditMode,
    pub pipe: Arc<InboundPipe>,
}

pub(crate) struct FinishedEncoding {
    pub(crate) bytes: Vec<u8>,
    pub(crate) subpaths: Vec<PendingOutboundSubpath>,
    pub(crate) inserted_handles: Vec<u32>,
    pub(crate) remote_handles: Vec<(PeerHandle, u32)>,
}

/// Binary wire encoder carrying connection resource-table access and sub-path
/// allocation for an invocation.
pub struct Encoder<'a, R: ResourceEntry = core::convert::Infallible> {
    bytes: Vec<u8>,
    call: Option<&'a CallHandle>,
    resources: Option<&'a mut ResourceTableInner<R>>,
    resource_table: Option<&'a ResourceTable<R>>,
    spawner: Option<&'a SubpathSpawner>,
    outbound_subpaths: Vec<PendingOutboundSubpath>,
    inserted_handles: Vec<u32>,
    transferred_remote_handles: Vec<(PeerHandle, u32)>,
}

impl<'a, R: ResourceEntry> Encoder<'a, R> {
    pub fn new(
        call: Option<&'a CallHandle>,
        resources: Option<&'a mut ResourceTableInner<R>>,
    ) -> Self {
        Self::with_context(call, resources, None, None)
    }

    pub(crate) fn with_context(
        call: Option<&'a CallHandle>,
        resources: Option<&'a mut ResourceTableInner<R>>,
        resource_table: Option<&'a ResourceTable<R>>,
        spawner: Option<&'a SubpathSpawner>,
    ) -> Self {
        Self {
            bytes: Vec::new(),
            call,
            resources,
            resource_table,
            spawner,
            outbound_subpaths: Vec::new(),
            inserted_handles: Vec::new(),
            transferred_remote_handles: Vec::new(),
        }
    }

    pub fn call_handle(&self) -> Option<&'a CallHandle> {
        self.call
    }

    pub(crate) fn resource_table(&self) -> Option<&'a ResourceTable<R>> {
        self.resource_table
    }

    pub(crate) fn spawner(&self) -> Option<&'a SubpathSpawner> {
        self.spawner
    }

    pub fn resources_mut(&mut self) -> Result<&mut ResourceTableInner<R>, WireError> {
        self.resources
            .as_deref_mut()
            .ok_or_else(|| WireError::MalformedPayload {
                context: "Encoder::resources_mut".to_owned(),
                detail: "resource table is unavailable in this encoding context".to_owned(),
            })
    }

    /// Inserts a newly exported `own<R>` resource into the connection table and
    /// records its handle so encoding errors or cancelled transmission can roll
    /// it back without leaking table entries.
    pub fn insert_resource(&mut self, value: R) -> Result<u32, WireError> {
        let handle = self.resources_mut()?.insert(value)?;
        self.inserted_handles.push(handle);
        Ok(handle)
    }

    pub(crate) fn record_inserted_handle(&mut self, handle: u32) {
        self.inserted_handles.push(handle);
    }

    pub(crate) fn record_transferred_remote_handle(&mut self, peer: PeerHandle, handle: u32) {
        self.transferred_remote_handles.push((peer, handle));
    }

    pub fn alloc_subpath_id(&self) -> Result<u32, WireError> {
        self.call
            .map(CallHandle::alloc_subpath_id)
            .ok_or_else(|| WireError::MalformedPayload {
                context: "Encoder::alloc_subpath_id".to_owned(),
                detail: "stream or future cannot be encoded outside an active invocation"
                    .to_owned(),
            })
    }

    pub fn push_outbound_subpath(&mut self, pending: PendingOutboundSubpath) {
        self.outbound_subpaths.push(pending);
    }

    pub fn finish(self) -> (Vec<u8>, Vec<PendingOutboundSubpath>) {
        (self.bytes, self.outbound_subpaths)
    }

    pub(crate) fn finish_full(self) -> FinishedEncoding {
        FinishedEncoding {
            bytes: self.bytes,
            subpaths: self.outbound_subpaths,
            inserted_handles: self.inserted_handles,
            remote_handles: self.transferred_remote_handles,
        }
    }

    pub(crate) fn take_inserted_handles(&mut self) -> Vec<u32> {
        std::mem::take(&mut self.inserted_handles)
    }

    pub(crate) fn take_transferred_remote_handles(&mut self) -> Vec<(PeerHandle, u32)> {
        std::mem::take(&mut self.transferred_remote_handles)
    }

    /// Runs a child encoding pass into a separate byte buffer while sharing
    /// this encoder's `ResourceTableInner` borrow and forwarding nested
    /// sub-paths and handle rollback state back into `self`.
    pub(crate) fn encode_nested_frame(
        &mut self,
        write: impl FnOnce(&mut Encoder<'_, R>) -> Result<(), WireError>,
    ) -> Result<Vec<u8>, WireError> {
        let mut child = Encoder {
            bytes: Vec::new(),
            call: self.call,
            resources: self.resources.as_deref_mut(),
            resource_table: self.resource_table,
            spawner: self.spawner,
            outbound_subpaths: Vec::new(),
            inserted_handles: Vec::new(),
            transferred_remote_handles: Vec::new(),
        };
        let res = write(&mut child);
        let finished = child.finish_full();
        for handle in finished.inserted_handles {
            self.record_inserted_handle(handle);
        }
        for (peer, handle) in finished.remote_handles {
            self.record_transferred_remote_handle(peer, handle);
        }
        match res {
            Ok(()) => {
                for sub in finished.subpaths {
                    self.push_outbound_subpath(sub);
                }
                Ok(finished.bytes)
            }
            Err(err) => Err(err),
        }
    }

    pub fn write_u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    pub fn write_u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    pub fn write_u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    pub fn write_u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    pub fn write_bytes(&mut self, slice: &[u8]) -> Result<(), WireError> {
        let len = u32::try_from(slice.len()).map_err(|_| WireError::MalformedPayload {
            context: "Encoder::write_bytes".to_owned(),
            detail: "byte slice length exceeds u32::MAX".to_owned(),
        })?;
        self.write_u32(len);
        self.bytes.extend_from_slice(slice);
        Ok(())
    }
}

/// Binary wire decoder with overflow-checked length bounds, connection
/// resource-table access, and sub-path registration.
pub struct Decoder<'a, R: ResourceEntry = core::convert::Infallible> {
    cursor: &'a [u8],
    peer: PeerHandle,
    default_stream_window: u32,
    resources: Option<&'a mut ResourceTableInner<R>>,
    resource_table: Option<&'a ResourceTable<R>>,
    spawner: Option<&'a SubpathSpawner>,
    inbound_subpaths: Vec<PendingInboundSubpath>,
}

impl<'a, R: ResourceEntry> Decoder<'a, R> {
    pub fn new(
        bytes: &'a [u8],
        peer: PeerHandle,
        resources: Option<&'a mut ResourceTableInner<R>>,
    ) -> Self {
        Self::with_context(bytes, peer, resources, None, None)
    }

    pub(crate) fn with_context(
        bytes: &'a [u8],
        peer: PeerHandle,
        resources: Option<&'a mut ResourceTableInner<R>>,
        resource_table: Option<&'a ResourceTable<R>>,
        spawner: Option<&'a SubpathSpawner>,
    ) -> Self {
        let default_stream_window = peer.stream_credit_window();
        Self {
            cursor: bytes,
            peer,
            default_stream_window,
            resources,
            resource_table,
            spawner,
            inbound_subpaths: Vec::new(),
        }
    }

    pub fn peer(&self) -> &PeerHandle {
        &self.peer
    }

    pub fn default_stream_window(&self) -> u32 {
        self.default_stream_window
    }

    pub(crate) fn resource_table(&self) -> Option<&'a ResourceTable<R>> {
        self.resource_table
    }

    pub(crate) fn spawner(&self) -> Option<&'a SubpathSpawner> {
        self.spawner
    }

    pub fn resources(&self) -> Result<&ResourceTableInner<R>, WireError> {
        self.resources
            .as_deref()
            .ok_or_else(|| WireError::MalformedPayload {
                context: "Decoder::resources".to_owned(),
                detail: "resource table is unavailable in this decoding context".to_owned(),
            })
    }

    pub fn resources_mut(&mut self) -> Result<&mut ResourceTableInner<R>, WireError> {
        self.resources
            .as_deref_mut()
            .ok_or_else(|| WireError::MalformedPayload {
                context: "Decoder::resources_mut".to_owned(),
                detail: "resource table is unavailable in this decoding context".to_owned(),
            })
    }

    pub fn push_inbound_subpath(&mut self, pending: PendingInboundSubpath) {
        self.inbound_subpaths.push(pending);
    }

    pub fn finish(self) -> Result<Vec<PendingInboundSubpath>, WireError> {
        if !self.cursor.is_empty() {
            return Err(WireError::MalformedPayload {
                context: "Decoder::finish".to_owned(),
                detail: format!("{} trailing unconsumed byte(s)", self.cursor.len()),
            });
        }
        Ok(self.inbound_subpaths)
    }

    pub fn read_exact(
        &mut self,
        count: usize,
        context: &'static str,
    ) -> Result<&'a [u8], WireError> {
        if self.cursor.len() < count {
            return Err(WireError::MalformedPayload {
                context: context.to_owned(),
                detail: format!(
                    "expected {count} byte(s), only {} remaining",
                    self.cursor.len()
                ),
            });
        }
        let (head, tail) = self.cursor.split_at(count);
        self.cursor = tail;
        Ok(head)
    }

    pub fn read_u8(&mut self) -> Result<u8, WireError> {
        Ok(self.read_exact(1, "u8")?[0])
    }

    pub fn read_u16(&mut self) -> Result<u16, WireError> {
        let raw = self.read_exact(2, "u16")?;
        Ok(u16::from_le_bytes([raw[0], raw[1]]))
    }

    pub fn read_u32(&mut self) -> Result<u32, WireError> {
        let raw = self.read_exact(4, "u32")?;
        Ok(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
    }

    pub fn read_u64(&mut self) -> Result<u64, WireError> {
        let raw = self.read_exact(8, "u64")?;
        Ok(u64::from_le_bytes([
            raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
        ]))
    }

    /// Reads a `u32` element count after verifying `count * min_elem_bytes`
    /// cannot exceed remaining input bytes.
    pub fn read_checked_len(
        &mut self,
        field: &'static str,
        min_elem_bytes: usize,
    ) -> Result<usize, WireError> {
        let count = self.read_u32()?;
        let remaining = self.cursor.len();
        let needed = usize::try_from(count)
            .ok()
            .and_then(|n| n.checked_mul(min_elem_bytes))
            .unwrap_or(usize::MAX);
        if needed > remaining {
            return Err(WireError::LengthExceedsInput {
                field,
                len: count,
                needed,
                remaining,
            });
        }
        usize::try_from(count).map_err(|_| WireError::LengthExceedsInput {
            field,
            len: count,
            needed: usize::MAX,
            remaining,
        })
    }

    pub fn read_bytes(&mut self, field: &'static str) -> Result<&'a [u8], WireError> {
        let len = self.read_checked_len(field, 1)?;
        self.read_exact(len, field)
    }
}

/// Activates all outbound sub-paths allocated during an [`Encoder`] pass
/// before the message referencing their IDs hits the wire, returning cancel
/// tokens for any spawned pre-buffered pump tasks.
pub(crate) async fn activate_outbound_subpaths_tracked(
    call: &CallHandle,
    subpaths: Vec<PendingOutboundSubpath>,
) -> Vec<Arc<SubpathCancelToken>> {
    let mut cancels = Vec::new();
    for pending in subpaths {
        match pending.0 {
            PendingOutboundSubpathKind::Live { sub_id, bind } => {
                let writer = call.register_writer(sub_id).await;
                bind.bind(writer).await;
            }
            PendingOutboundSubpathKind::Buffered { sub_id, frames } => {
                call.register_buffered(sub_id, frames).await;
            }
            PendingOutboundSubpathKind::Pumped {
                sub_id,
                spawner,
                cancel,
                pump,
            } => {
                let writer = call.register_writer(sub_id).await;
                spawner.spawn(pump.into_task(writer, Arc::clone(&cancel)));
                cancels.push(cancel);
            }
            PendingOutboundSubpathKind::Empty { sub_id } => {
                call.register_empty(sub_id);
            }
        }
    }
    cancels
}

/// Activates all outbound sub-paths allocated during an [`Encoder`] pass
/// before the message referencing their IDs hits the wire.
pub async fn activate_outbound_subpaths(call: &CallHandle, subpaths: Vec<PendingOutboundSubpath>) {
    let _ = activate_outbound_subpaths_tracked(call, subpaths).await;
}

/// Activates all inbound sub-paths decoded during a [`Decoder`] pass and sends
/// their initial credit grants before returning the decoded values.
pub async fn activate_inbound_subpaths(
    call: &CallHandle,
    subpaths: Vec<PendingInboundSubpath>,
) -> Result<(), RpcError> {
    for pending in subpaths {
        let reader = match pending.credit_mode {
            SubpathCreditMode::Streaming { window } => {
                call.open_reader(pending.sub_id, window).await?
            }
            SubpathCreditMode::Oneshot => call.open_oneshot_reader(pending.sub_id).await?,
        };
        pending.pipe.install(reader).await;
    }
    Ok(())
}

/// Encodes a client-side request value onto `call` and activates any nested
/// outbound `stream<T>` / `future<T>` sub-paths.
pub async fn encode_client_value<T: RpcEncode<core::convert::Infallible>>(
    call: &OutboundCall,
    value: T,
) -> Result<Vec<u8>, RpcError> {
    let handle = call.call_handle();
    let mut encoder = Encoder::<core::convert::Infallible>::new(Some(&handle), None);
    if let Err(err) = value.rpc_encode(&mut encoder) {
        rollback_remote_handles(encoder.take_transferred_remote_handles());
        return Err(RpcError::Wire(err));
    }
    let (bytes, subpaths) = encoder.finish();
    activate_outbound_subpaths(&handle, subpaths).await;
    Ok(bytes)
}

/// Encodes and transmits a client-side request value onto `call`, activating
/// nested outbound sub-paths and rolling back transferred `RemoteResource`
/// handles if encoding, transmission, or cancellation fails before delivery.
pub async fn send_client_value<T: RpcEncode<core::convert::Infallible>>(
    call: &OutboundCall,
    value: T,
) -> Result<(), RpcError> {
    let handle = call.call_handle();
    let mut encoder = Encoder::<core::convert::Infallible>::new(Some(&handle), None);
    if let Err(err) = value.rpc_encode(&mut encoder) {
        rollback_remote_handles(encoder.take_transferred_remote_handles());
        return Err(RpcError::Wire(err));
    }
    let finished = encoder.finish_full();
    let mut guard =
        SendRollbackGuard::new(EncodedHandlesRollback::remote_only(finished.remote_handles));
    let cancels = activate_outbound_subpaths_tracked(&handle, finished.subpaths).await;
    guard.add_cancels(cancels);
    match call.send_root_request(&finished.bytes).await {
        Ok(()) => {
            guard.disarm();
            Ok(())
        }
        Err(err) => {
            guard.rollback_now().await;
            Err(RpcError::from(err))
        }
    }
}

/// Decodes a client-side response value from `bytes` on `call` and activates
/// any nested inbound `stream<T>` / `future<T>` sub-paths.
pub async fn decode_client_value<T: RpcDecode<core::convert::Infallible>>(
    call: &OutboundCall,
    bytes: &[u8],
) -> Result<T, RpcError> {
    let handle = call.call_handle();
    let mut decoder = Decoder::<core::convert::Infallible>::new(bytes, call.peer(), None);
    let value = T::rpc_decode(&mut decoder)?;
    let subpaths = decoder.finish()?;
    activate_inbound_subpaths(&handle, subpaths).await?;
    Ok(value)
}

/// Server-side helper to decode request parameters with access to the
/// connection's [`ResourceTable`], releasing the table lock before `.await`.
pub(crate) async fn decode_server_request<R, T>(
    call: &InboundCall,
    resources: &ResourceTable<R>,
    spawner: Option<&SubpathSpawner>,
    bytes: &[u8],
) -> Result<T, WireError>
where
    R: ResourceEntry,
    T: RpcDecode<R>,
{
    let handle = call.call_handle();
    let outcome = {
        let mut table = resources.lock().await;
        let mut decoder = Decoder::with_context(
            bytes,
            call.peer().clone(),
            Some(&mut *table),
            Some(resources),
            spawner,
        );
        match T::rpc_decode(&mut decoder) {
            Ok(value) => match decoder.finish() {
                Ok(subpaths) => Ok((value, subpaths)),
                Err(err) => Err((err, Some(value))),
            },
            Err(err) => Err((err, None)),
        }
    };
    let (value, subpaths) = match outcome {
        Ok(pair) => pair,
        Err((err, dropped)) => {
            drop(dropped);
            return Err(err);
        }
    };
    for pending in subpaths {
        let open_res = match pending.credit_mode {
            SubpathCreditMode::Streaming { window } => {
                handle.open_reader(pending.sub_id, window).await
            }
            SubpathCreditMode::Oneshot => handle.open_oneshot_reader(pending.sub_id).await,
        };
        let reader = open_res.map_err(|err| match err.wire_error() {
            Some(wire) => wire.clone(),
            None => WireError::MalformedPayload {
                context: "open_reader".to_owned(),
                detail: err.to_string(),
            },
        })?;
        pending.pipe.install(reader).await;
    }
    Ok(value)
}

/// Encoded server response payload plus the outbound sub-paths and `own<R>`
/// resource handles inserted during encoding so callers can roll handles back
/// if response transmission fails or is cancelled mid-`.await`.
pub(crate) struct EncodedServerResponse {
    pub(crate) bytes: Vec<u8>,
    pub(crate) subpaths: Vec<PendingOutboundSubpath>,
    pub(crate) inserted_handles: Vec<u32>,
    pub(crate) remote_handles: Vec<(PeerHandle, u32)>,
}

/// Server-side helper to encode response values with access to the
/// connection's [`ResourceTable`], releasing the table lock before `.await` and
/// rolling back any partially inserted handles if encoding itself fails.
pub(crate) async fn encode_server_response<R, T>(
    call: &InboundCall,
    resources: &ResourceTable<R>,
    spawner: Option<&SubpathSpawner>,
    value: T,
) -> Result<EncodedServerResponse, WireError>
where
    R: ResourceEntry,
    T: RpcEncode<R>,
{
    let handle = call.call_handle();
    let encoded = {
        let mut table = resources.lock().await;
        let mut encoder =
            Encoder::with_context(Some(&handle), Some(&mut *table), Some(resources), spawner);
        match value.rpc_encode(&mut encoder) {
            Ok(()) => {
                let finished = encoder.finish_full();
                Ok(EncodedServerResponse {
                    bytes: finished.bytes,
                    subpaths: finished.subpaths,
                    inserted_handles: finished.inserted_handles,
                    remote_handles: finished.remote_handles,
                })
            }
            Err(err) => {
                let handles = encoder.take_inserted_handles();
                let remote = encoder.take_transferred_remote_handles();
                drop(encoder);
                let mut rolled_back = Vec::with_capacity(handles.len());
                for id in handles {
                    if let Some(entry) = table.remove_unconditional(id) {
                        rolled_back.push(entry);
                    }
                }
                Err((err, rolled_back, remote))
            }
        }
    };
    match encoded {
        Ok(resp) => Ok(resp),
        Err((err, rolled_back, remote)) => {
            drop(rolled_back);
            rollback_remote_handles(remote);
            Err(err)
        }
    }
}

/// Wire encoding contract for WIT values, handles, streams, and futures.
pub trait RpcEncode<R: ResourceEntry = core::convert::Infallible>: Sized {
    /// Minimum wire size in bytes of one encoded element (used for checked
    /// `Vec<T>` length pre-validation).
    const MIN_WIRE_SIZE: usize = 1;

    /// Whether encoding this type may lower `own<R>` handles into a
    /// [`ResourceTable`] or transfer [`RemoteResource`] ownership.
    const CONTAINS_RESOURCES: bool = false;

    fn rpc_encode(self, enc: &mut Encoder<'_, R>) -> Result<(), WireError>;

    /// Fast-path slice encoding hook overridden by `u8`.
    fn rpc_encode_vec(items: Vec<Self>, enc: &mut Encoder<'_, R>) -> Result<(), WireError> {
        let len = u32::try_from(items.len()).map_err(|_| WireError::MalformedPayload {
            context: "Vec::rpc_encode".to_owned(),
            detail: "list length exceeds u32::MAX".to_owned(),
        })?;
        enc.write_u32(len);
        for item in items {
            item.rpc_encode(enc)?;
        }
        Ok(())
    }
}

/// Wire decoding contract for WIT values, handles, streams, and futures.
pub trait RpcDecode<R: ResourceEntry = core::convert::Infallible>: Sized {
    const MIN_WIRE_SIZE: usize = 1;

    /// Whether decoding this type may lift `own<R>` handles from a
    /// [`ResourceTable`] or construct [`RemoteResource`] proxies.
    const CONTAINS_RESOURCES: bool = false;

    fn rpc_decode(dec: &mut Decoder<'_, R>) -> Result<Self, WireError>;

    fn rpc_decode_vec(dec: &mut Decoder<'_, R>) -> Result<Vec<Self>, WireError> {
        let len = dec.read_checked_len("list", Self::MIN_WIRE_SIZE)?;
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            out.push(Self::rpc_decode(dec)?);
        }
        Ok(out)
    }
}

impl<R: ResourceEntry> RpcEncode<R> for () {
    const MIN_WIRE_SIZE: usize = 0;

    fn rpc_encode(self, _enc: &mut Encoder<'_, R>) -> Result<(), WireError> {
        Ok(())
    }
}

impl<R: ResourceEntry> RpcDecode<R> for () {
    const MIN_WIRE_SIZE: usize = 0;

    fn rpc_decode(_dec: &mut Decoder<'_, R>) -> Result<Self, WireError> {
        Ok(())
    }
}

impl<R: ResourceEntry> RpcEncode<R> for bool {
    fn rpc_encode(self, enc: &mut Encoder<'_, R>) -> Result<(), WireError> {
        enc.write_u8(u8::from(self));
        Ok(())
    }
}

impl<R: ResourceEntry> RpcDecode<R> for bool {
    fn rpc_decode(dec: &mut Decoder<'_, R>) -> Result<Self, WireError> {
        match dec.read_u8()? {
            0 => Ok(false),
            1 => Ok(true),
            other => Err(WireError::MalformedPayload {
                context: "bool".to_owned(),
                detail: format!("invalid bool discriminant {other}"),
            }),
        }
    }
}

impl<R: ResourceEntry> RpcEncode<R> for u8 {
    fn rpc_encode(self, enc: &mut Encoder<'_, R>) -> Result<(), WireError> {
        enc.write_u8(self);
        Ok(())
    }

    fn rpc_encode_vec(items: Vec<Self>, enc: &mut Encoder<'_, R>) -> Result<(), WireError> {
        enc.write_bytes(&items)
    }
}

impl<R: ResourceEntry> RpcDecode<R> for u8 {
    fn rpc_decode(dec: &mut Decoder<'_, R>) -> Result<Self, WireError> {
        dec.read_u8()
    }

    fn rpc_decode_vec(dec: &mut Decoder<'_, R>) -> Result<Vec<Self>, WireError> {
        Ok(dec.read_bytes("byte slice")?.to_vec())
    }
}

impl<R: ResourceEntry> RpcEncode<R> for i8 {
    fn rpc_encode(self, enc: &mut Encoder<'_, R>) -> Result<(), WireError> {
        enc.write_u8(self.to_le_bytes()[0]);
        Ok(())
    }
}

impl<R: ResourceEntry> RpcDecode<R> for i8 {
    fn rpc_decode(dec: &mut Decoder<'_, R>) -> Result<Self, WireError> {
        Ok(Self::from_le_bytes([dec.read_u8()?]))
    }
}

impl<R: ResourceEntry> RpcEncode<R> for u16 {
    const MIN_WIRE_SIZE: usize = 2;

    fn rpc_encode(self, enc: &mut Encoder<'_, R>) -> Result<(), WireError> {
        enc.write_u16(self);
        Ok(())
    }
}

impl<R: ResourceEntry> RpcDecode<R> for u16 {
    const MIN_WIRE_SIZE: usize = 2;

    fn rpc_decode(dec: &mut Decoder<'_, R>) -> Result<Self, WireError> {
        dec.read_u16()
    }
}

impl<R: ResourceEntry> RpcEncode<R> for i16 {
    const MIN_WIRE_SIZE: usize = 2;

    fn rpc_encode(self, enc: &mut Encoder<'_, R>) -> Result<(), WireError> {
        enc.write_u16(u16::from_le_bytes(self.to_le_bytes()));
        Ok(())
    }
}

impl<R: ResourceEntry> RpcDecode<R> for i16 {
    const MIN_WIRE_SIZE: usize = 2;

    fn rpc_decode(dec: &mut Decoder<'_, R>) -> Result<Self, WireError> {
        Ok(Self::from_le_bytes(dec.read_u16()?.to_le_bytes()))
    }
}

impl<R: ResourceEntry> RpcEncode<R> for u32 {
    const MIN_WIRE_SIZE: usize = 4;

    fn rpc_encode(self, enc: &mut Encoder<'_, R>) -> Result<(), WireError> {
        enc.write_u32(self);
        Ok(())
    }
}

impl<R: ResourceEntry> RpcDecode<R> for u32 {
    const MIN_WIRE_SIZE: usize = 4;

    fn rpc_decode(dec: &mut Decoder<'_, R>) -> Result<Self, WireError> {
        dec.read_u32()
    }
}

impl<R: ResourceEntry> RpcEncode<R> for i32 {
    const MIN_WIRE_SIZE: usize = 4;

    fn rpc_encode(self, enc: &mut Encoder<'_, R>) -> Result<(), WireError> {
        enc.write_u32(u32::from_le_bytes(self.to_le_bytes()));
        Ok(())
    }
}

impl<R: ResourceEntry> RpcDecode<R> for i32 {
    const MIN_WIRE_SIZE: usize = 4;

    fn rpc_decode(dec: &mut Decoder<'_, R>) -> Result<Self, WireError> {
        Ok(Self::from_le_bytes(dec.read_u32()?.to_le_bytes()))
    }
}

impl<R: ResourceEntry> RpcEncode<R> for u64 {
    const MIN_WIRE_SIZE: usize = 8;

    fn rpc_encode(self, enc: &mut Encoder<'_, R>) -> Result<(), WireError> {
        enc.write_u64(self);
        Ok(())
    }
}

impl<R: ResourceEntry> RpcDecode<R> for u64 {
    const MIN_WIRE_SIZE: usize = 8;

    fn rpc_decode(dec: &mut Decoder<'_, R>) -> Result<Self, WireError> {
        dec.read_u64()
    }
}

impl<R: ResourceEntry> RpcEncode<R> for i64 {
    const MIN_WIRE_SIZE: usize = 8;

    fn rpc_encode(self, enc: &mut Encoder<'_, R>) -> Result<(), WireError> {
        enc.write_u64(u64::from_le_bytes(self.to_le_bytes()));
        Ok(())
    }
}

impl<R: ResourceEntry> RpcDecode<R> for i64 {
    const MIN_WIRE_SIZE: usize = 8;

    fn rpc_decode(dec: &mut Decoder<'_, R>) -> Result<Self, WireError> {
        Ok(Self::from_le_bytes(dec.read_u64()?.to_le_bytes()))
    }
}

impl<R: ResourceEntry> RpcEncode<R> for f32 {
    const MIN_WIRE_SIZE: usize = 4;

    fn rpc_encode(self, enc: &mut Encoder<'_, R>) -> Result<(), WireError> {
        enc.write_u32(self.to_bits());
        Ok(())
    }
}

impl<R: ResourceEntry> RpcDecode<R> for f32 {
    const MIN_WIRE_SIZE: usize = 4;

    fn rpc_decode(dec: &mut Decoder<'_, R>) -> Result<Self, WireError> {
        Ok(Self::from_bits(dec.read_u32()?))
    }
}

impl<R: ResourceEntry> RpcEncode<R> for f64 {
    const MIN_WIRE_SIZE: usize = 8;

    fn rpc_encode(self, enc: &mut Encoder<'_, R>) -> Result<(), WireError> {
        enc.write_u64(self.to_bits());
        Ok(())
    }
}

impl<R: ResourceEntry> RpcDecode<R> for f64 {
    const MIN_WIRE_SIZE: usize = 8;

    fn rpc_decode(dec: &mut Decoder<'_, R>) -> Result<Self, WireError> {
        Ok(Self::from_bits(dec.read_u64()?))
    }
}

impl<R: ResourceEntry> RpcEncode<R> for char {
    const MIN_WIRE_SIZE: usize = 4;

    fn rpc_encode(self, enc: &mut Encoder<'_, R>) -> Result<(), WireError> {
        enc.write_u32(u32::from(self));
        Ok(())
    }
}

impl<R: ResourceEntry> RpcDecode<R> for char {
    const MIN_WIRE_SIZE: usize = 4;

    fn rpc_decode(dec: &mut Decoder<'_, R>) -> Result<Self, WireError> {
        let raw = dec.read_u32()?;
        Self::from_u32(raw).ok_or_else(|| WireError::MalformedPayload {
            context: "char".to_owned(),
            detail: format!("invalid Unicode scalar value {raw:#x}"),
        })
    }
}

impl<R: ResourceEntry> RpcEncode<R> for String {
    const MIN_WIRE_SIZE: usize = 4;

    fn rpc_encode(self, enc: &mut Encoder<'_, R>) -> Result<(), WireError> {
        enc.write_bytes(self.as_bytes())
    }
}

impl<R: ResourceEntry> RpcDecode<R> for String {
    const MIN_WIRE_SIZE: usize = 4;

    fn rpc_decode(dec: &mut Decoder<'_, R>) -> Result<Self, WireError> {
        let bytes = dec.read_bytes("string")?;
        std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|err| WireError::MalformedPayload {
                context: "string".to_owned(),
                detail: err.to_string(),
            })
    }
}

impl<R: ResourceEntry> RpcEncode<R> for ErrorContext {
    const MIN_WIRE_SIZE: usize = 4;

    fn rpc_encode(self, enc: &mut Encoder<'_, R>) -> Result<(), WireError> {
        self.debug_message.rpc_encode(enc)
    }
}

impl<R: ResourceEntry> RpcDecode<R> for ErrorContext {
    const MIN_WIRE_SIZE: usize = 4;

    fn rpc_decode(dec: &mut Decoder<'_, R>) -> Result<Self, WireError> {
        Ok(Self {
            debug_message: String::rpc_decode(dec)?,
        })
    }
}

impl<R: ResourceEntry, T: RpcEncode<R>> RpcEncode<R> for Vec<T> {
    const MIN_WIRE_SIZE: usize = 4;
    const CONTAINS_RESOURCES: bool = T::CONTAINS_RESOURCES;

    fn rpc_encode(self, enc: &mut Encoder<'_, R>) -> Result<(), WireError> {
        T::rpc_encode_vec(self, enc)
    }
}

impl<R: ResourceEntry, T: RpcDecode<R>> RpcDecode<R> for Vec<T> {
    const MIN_WIRE_SIZE: usize = 4;
    const CONTAINS_RESOURCES: bool = T::CONTAINS_RESOURCES;

    fn rpc_decode(dec: &mut Decoder<'_, R>) -> Result<Self, WireError> {
        T::rpc_decode_vec(dec)
    }
}

impl<R: ResourceEntry, T: RpcEncode<R>, const N: usize> RpcEncode<R> for [T; N] {
    const MIN_WIRE_SIZE: usize = N * T::MIN_WIRE_SIZE;
    const CONTAINS_RESOURCES: bool = T::CONTAINS_RESOURCES;

    fn rpc_encode(self, enc: &mut Encoder<'_, R>) -> Result<(), WireError> {
        for item in self {
            item.rpc_encode(enc)?;
        }
        Ok(())
    }
}

impl<R: ResourceEntry, T: RpcDecode<R>, const N: usize> RpcDecode<R> for [T; N] {
    const MIN_WIRE_SIZE: usize = N * T::MIN_WIRE_SIZE;
    const CONTAINS_RESOURCES: bool = T::CONTAINS_RESOURCES;

    fn rpc_decode(dec: &mut Decoder<'_, R>) -> Result<Self, WireError> {
        let mut items = Vec::with_capacity(N);
        for _ in 0..N {
            items.push(T::rpc_decode(dec)?);
        }
        items.try_into().map_err(|_| WireError::MalformedPayload {
            context: "fixed-length list".to_owned(),
            detail: "fixed-length array conversion failed".to_owned(),
        })
    }
}

impl<R: ResourceEntry, T: RpcEncode<R>> RpcEncode<R> for Option<T> {
    const CONTAINS_RESOURCES: bool = T::CONTAINS_RESOURCES;

    fn rpc_encode(self, enc: &mut Encoder<'_, R>) -> Result<(), WireError> {
        match self {
            None => enc.write_u8(0),
            Some(val) => {
                enc.write_u8(1);
                val.rpc_encode(enc)?;
            }
        }
        Ok(())
    }
}

impl<R: ResourceEntry, T: RpcDecode<R>> RpcDecode<R> for Option<T> {
    const CONTAINS_RESOURCES: bool = T::CONTAINS_RESOURCES;

    fn rpc_decode(dec: &mut Decoder<'_, R>) -> Result<Self, WireError> {
        match dec.read_u8()? {
            0 => Ok(None),
            1 => Ok(Some(T::rpc_decode(dec)?)),
            other => Err(WireError::MalformedPayload {
                context: "option".to_owned(),
                detail: format!("invalid option discriminant {other}"),
            }),
        }
    }
}

impl<R: ResourceEntry, O: RpcEncode<R>, E: RpcEncode<R>> RpcEncode<R> for Result<O, E> {
    const CONTAINS_RESOURCES: bool = O::CONTAINS_RESOURCES || E::CONTAINS_RESOURCES;

    fn rpc_encode(self, enc: &mut Encoder<'_, R>) -> Result<(), WireError> {
        match self {
            Ok(ok) => {
                enc.write_u8(0);
                ok.rpc_encode(enc)
            }
            Err(err) => {
                enc.write_u8(1);
                err.rpc_encode(enc)
            }
        }
    }
}

impl<R: ResourceEntry, O: RpcDecode<R>, E: RpcDecode<R>> RpcDecode<R> for Result<O, E> {
    const CONTAINS_RESOURCES: bool = O::CONTAINS_RESOURCES || E::CONTAINS_RESOURCES;

    fn rpc_decode(dec: &mut Decoder<'_, R>) -> Result<Self, WireError> {
        match dec.read_u8()? {
            0 => Ok(Ok(O::rpc_decode(dec)?)),
            1 => Ok(Err(E::rpc_decode(dec)?)),
            other => Err(WireError::MalformedPayload {
                context: "result".to_owned(),
                detail: format!("invalid result discriminant {other}"),
            }),
        }
    }
}

impl<R: ResourceEntry> RpcEncode<R> for RemoteResource {
    const MIN_WIRE_SIZE: usize = 4;
    const CONTAINS_RESOURCES: bool = true;

    fn rpc_encode(self, enc: &mut Encoder<'_, R>) -> Result<(), WireError> {
        let (peer, handle, was_owned) = self.into_raw_handle_checked();
        if was_owned {
            enc.record_transferred_remote_handle(peer, handle);
        }
        enc.write_u32(handle);
        Ok(())
    }
}

impl<R: ResourceEntry> RpcEncode<R> for &RemoteResource {
    const MIN_WIRE_SIZE: usize = 4;

    fn rpc_encode(self, enc: &mut Encoder<'_, R>) -> Result<(), WireError> {
        enc.write_u32(self.handle_id());
        Ok(())
    }
}

impl<R: ResourceEntry> RpcDecode<R> for RemoteResource {
    const MIN_WIRE_SIZE: usize = 4;
    const CONTAINS_RESOURCES: bool = true;

    fn rpc_decode(dec: &mut Decoder<'_, R>) -> Result<Self, WireError> {
        let handle = dec.read_u32()?;
        if handle == 0 {
            return Err(WireError::InvalidResourceHandle { handle });
        }
        Ok(Self::new(dec.peer().clone(), handle))
    }
}

impl<R: ResourceEntry, T: RpcEncode<R> + MaybeSend + 'static> RpcEncode<R> for StreamReader<T> {
    const MIN_WIRE_SIZE: usize = 4;
    const CONTAINS_RESOURCES: bool = T::CONTAINS_RESOURCES;

    fn rpc_encode(self, enc: &mut Encoder<'_, R>) -> Result<(), WireError> {
        self.encode_into_subpath(enc)
    }
}

impl<R: ResourceEntry, T: RpcDecode<R> + MaybeSend + 'static> RpcDecode<R> for StreamReader<T> {
    const MIN_WIRE_SIZE: usize = 4;
    const CONTAINS_RESOURCES: bool = T::CONTAINS_RESOURCES;

    fn rpc_decode(dec: &mut Decoder<'_, R>) -> Result<Self, WireError> {
        Self::decode_from_subpath(dec)
    }
}

impl<R: ResourceEntry, T: RpcEncode<R> + MaybeSend + 'static> RpcEncode<R> for FutureReader<T> {
    const MIN_WIRE_SIZE: usize = 4;
    const CONTAINS_RESOURCES: bool = T::CONTAINS_RESOURCES;

    fn rpc_encode(self, enc: &mut Encoder<'_, R>) -> Result<(), WireError> {
        self.encode_into_subpath(enc)
    }
}

impl<R: ResourceEntry, T: RpcDecode<R> + MaybeSend + 'static> RpcDecode<R> for FutureReader<T> {
    const MIN_WIRE_SIZE: usize = 4;
    const CONTAINS_RESOURCES: bool = T::CONTAINS_RESOURCES;

    fn rpc_decode(dec: &mut Decoder<'_, R>) -> Result<Self, WireError> {
        Self::decode_from_subpath(dec)
    }
}

macro_rules! impl_tuple_codec {
    ($(($($idx:tt : $T:ident),+)),+ $(,)?) => {
        $(
            impl<R: ResourceEntry, $($T: RpcEncode<R>),+> RpcEncode<R> for ($($T,)+) {
                const MIN_WIRE_SIZE: usize = 0 $(+ <$T as RpcEncode<R>>::MIN_WIRE_SIZE)+;
                const CONTAINS_RESOURCES: bool = false $(|| <$T as RpcEncode<R>>::CONTAINS_RESOURCES)+;

                fn rpc_encode(self, enc: &mut Encoder<'_, R>) -> Result<(), WireError> {
                    $(self.$idx.rpc_encode(enc)?;)+
                    Ok(())
                }
            }

            impl<R: ResourceEntry, $($T: RpcDecode<R>),+> RpcDecode<R> for ($($T,)+) {
                const MIN_WIRE_SIZE: usize = 0 $(+ <$T as RpcDecode<R>>::MIN_WIRE_SIZE)+;
                const CONTAINS_RESOURCES: bool = false $(|| <$T as RpcDecode<R>>::CONTAINS_RESOURCES)+;

                fn rpc_decode(dec: &mut Decoder<'_, R>) -> Result<Self, WireError> {
                    Ok(($(<$T as RpcDecode<R>>::rpc_decode(dec)?,)+))
                }
            }
        )+
    };
}

impl_tuple_codec!(
    (0: T0),
    (0: T0, 1: T1),
    (0: T0, 1: T1, 2: T2),
    (0: T0, 1: T1, 2: T2, 3: T3),
    (0: T0, 1: T1, 2: T2, 3: T3, 4: T4),
    (0: T0, 1: T1, 2: T2, 3: T3, 4: T4, 5: T5),
    (0: T0, 1: T1, 2: T2, 3: T3, 4: T4, 5: T5, 6: T6),
    (0: T0, 1: T1, 2: T2, 3: T3, 4: T4, 5: T5, 6: T6, 7: T7),
    (0: T0, 1: T1, 2: T2, 3: T3, 4: T4, 5: T5, 6: T6, 7: T7, 8: T8),
    (0: T0, 1: T1, 2: T2, 3: T3, 4: T4, 5: T5, 6: T6, 7: T7, 8: T8, 9: T9),
);
