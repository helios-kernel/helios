use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures_core::Stream;
use helios_inspector_protocol::WireError;
use helios_inspector_protocol::mux::{MaybeSend, SubpathReader, SubpathWriter};

use crate::codec::{
    BoundSlotBinder, Decoder, DirectPipeBinder, Encoder, InboundDecoder, InboundPipe,
    MappedInboundDecoder, MappedOutboundSlot, OutboundEncoder, OutboundPipe, OutboundPipeNotify,
    OutboundSlot, PendingInboundSubpath, PendingOutboundPump, PendingOutboundSubpath,
    PipeOutboundSlot, RpcDecode, RpcEncode, SendRollbackGuard, SubpathCancelToken,
    SubpathCreditMode, SubpathTask, TableInboundDecoder, TableOutboundEncoder,
    activate_inbound_subpaths, activate_outbound_subpaths_tracked,
};
use crate::error::RpcError;
use crate::resource::ResourceEntry;

#[cfg(not(target_arch = "wasm32"))]
type FuturePollFuture<T> = Pin<Box<dyn Future<Output = Result<T, RpcError>> + Send + 'static>>;
#[cfg(target_arch = "wasm32")]
type FuturePollFuture<T> = Pin<Box<dyn Future<Output = Result<T, RpcError>> + 'static>>;

#[cfg(not(target_arch = "wasm32"))]
type StreamPollFuture<T> = Pin<
    Box<
        dyn Future<Output = (Option<SubpathReader>, Result<Option<Vec<T>>, RpcError>)>
            + Send
            + 'static,
    >,
>;
#[cfg(target_arch = "wasm32")]
type StreamPollFuture<T> = Pin<
    Box<dyn Future<Output = (Option<SubpathReader>, Result<Option<Vec<T>>, RpcError>)> + 'static>,
>;

/// Creates a credit-flow-controlled WIT `stream<T>` pair `(StreamWriter<T>, StreamReader<T>)`.
///
/// Pass the [`StreamReader`] across any WIT-RPC parameter or return value and
/// write items into [`StreamWriter`]; each `send` awaits explicit receiver
/// credit on the sub-path before transmitting.
pub fn stream<T>() -> (StreamWriter<T>, StreamReader<T>) {
    let pipe = Arc::new(OutboundPipe::new());
    (
        StreamWriter {
            pipe: Arc::clone(&pipe),
            bound: None,
            closed: false,
        },
        StreamReader {
            state: StreamReaderState::Outbound(Some(pipe)),
            decoder: None,
            buffered: VecDeque::new(),
            poll_fut: None,
        },
    )
}

/// Creates a single-shot WIT `future<T>` pair `(FutureWriter<T>, FutureReader<T>)`.
pub fn future<T>() -> (FutureWriter<T>, FutureReader<T>) {
    let pipe = Arc::new(OutboundPipe::new());
    (
        FutureWriter {
            pipe: Arc::clone(&pipe),
            bound: None,
            resolved: false,
        },
        FutureReader {
            state: FutureReaderState::Outbound(Some(pipe)),
            decoder: None,
            poll_fut: None,
        },
    )
}

/// Producer half of a WIT `stream<T>`.
pub struct StreamWriter<T> {
    pipe: Arc<OutboundPipe<T>>,
    bound: Option<(SubpathWriter, Arc<dyn OutboundEncoder<T>>)>,
    closed: bool,
}

impl<T> std::fmt::Debug for StreamWriter<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamWriter")
            .field("closed", &self.closed)
            .finish()
    }
}

impl<T> Drop for StreamWriter<T> {
    fn drop(&mut self) {
        if !self.closed {
            let _ = self.bound.take();
            self.pipe.mark_writer_dropped();
        }
    }
}

impl<T: MaybeSend + 'static> StreamWriter<T> {
    async fn ensure_bound(
        &mut self,
    ) -> Result<&mut (SubpathWriter, Arc<dyn OutboundEncoder<T>>), RpcError> {
        if self.bound.is_none() {
            if self.closed || self.pipe.is_closed_for_writer() {
                return Err(RpcError::StreamClosed);
            }
            self.pipe.wait_until_bound().await?;
            self.bound = self.pipe.take_bound().await;
        }
        self.bound.as_mut().ok_or(RpcError::StreamClosed)
    }

    /// Sends a single item on the stream, waiting for per-stream credit from
    /// the remote consumer when the window is full.
    pub async fn send(&mut self, item: T) -> Result<(), RpcError> {
        self.send_batch(vec![item]).await
    }

    /// Sends a non-empty batch of items in a single wire frame consuming 1
    /// stream credit.
    pub async fn send_batch(&mut self, items: Vec<T>) -> Result<(), RpcError> {
        if items.is_empty() {
            return Ok(());
        }
        if self.closed || self.pipe.is_closed_for_writer() {
            return Err(RpcError::StreamClosed);
        }
        let (writer, encoder) = self.ensure_bound().await?;
        if writer.is_peer_stopped() {
            return Err(RpcError::StreamClosed);
        }

        let call = writer.call_handle();
        let encoded = encoder.encode_batch(&call, items).resolve().await?;
        let mut guard = SendRollbackGuard::new(encoded.rollback);
        let cancels = activate_outbound_subpaths_tracked(&call, encoded.subpaths).await;
        guard.add_cancels(cancels);

        match writer.send(encoded.bytes).await {
            Ok(()) => {
                guard.disarm();
                Ok(())
            }
            Err(err) => {
                guard.rollback_now().await;
                Err(match err.wire_error() {
                    Some(wire) => RpcError::Wire(wire.clone()),
                    None => RpcError::StreamClosed,
                })
            }
        }
    }

    /// Sends orderly EOF on the stream.
    pub async fn close(mut self) -> Result<(), RpcError> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        let writer = if let Some((writer, _)) = self.bound.take() {
            Some(writer)
        } else {
            if self.pipe.wait_until_bound().await.is_err() {
                return Ok(());
            }
            self.pipe.take_writer_only().await
        };
        if let Some(writer) = writer {
            writer.close().await?;
        }
        Ok(())
    }

    /// Whether the remote consumer dropped its [`StreamReader`] or cancelled
    /// the invocation.
    pub async fn is_closed(&self) -> bool {
        if self.closed || self.pipe.is_closed_for_writer() {
            return true;
        }
        if let Some((writer, _)) = self.bound.as_ref() {
            return writer.is_peer_stopped();
        }
        self.pipe.is_peer_stopped().await
    }

    /// Waits until the remote consumer stops reading or disconnects.
    pub async fn closed(&self) {
        if let Some((writer, _)) = self.bound.as_ref() {
            writer.wait_peer_stopped().await;
            return;
        }
        if self.pipe.wait_until_bound().await.is_err() {
            return;
        }
        if let Some(stop_watch) = self.pipe.stop_watch().await {
            stop_watch.wait_peer_stopped().await;
        }
    }
}

struct StreamItemsPump<T> {
    items: Vec<T>,
    encoder: Arc<dyn OutboundEncoder<T>>,
}

impl<T: MaybeSend + 'static> PendingOutboundPump for StreamItemsPump<T> {
    fn into_task(
        self: Box<Self>,
        mut writer: SubpathWriter,
        cancel: Arc<SubpathCancelToken>,
    ) -> SubpathTask {
        let Self { items, encoder } = *self;
        Box::pin(async move {
            let call = writer.call_handle();
            for item in items {
                if cancel.is_cancelled() || writer.is_peer_stopped() {
                    return;
                }
                let encoded = match encoder.encode_batch(&call, vec![item]).resolve().await {
                    Ok(encoded) => encoded,
                    Err(_) => return,
                };
                let mut guard = SendRollbackGuard::new(encoded.rollback);
                let cancels = activate_outbound_subpaths_tracked(&call, encoded.subpaths).await;
                guard.add_cancels(cancels);

                let send_res = futures_lite::future::or(
                    async { Some(writer.send(encoded.bytes).await) },
                    async {
                        cancel.wait().await;
                        None
                    },
                )
                .await;
                match send_res {
                    Some(Ok(())) => guard.disarm(),
                    Some(Err(_)) | None => {
                        guard.rollback_now().await;
                        return;
                    }
                }
            }
            if !cancel.is_cancelled() {
                let _ = writer.close().await;
            }
        })
    }
}

enum StreamReaderState<T> {
    Outbound(Option<Arc<OutboundPipe<T>>>),
    OutboundMapped {
        slot: Option<Box<dyn OutboundSlot<T>>>,
        notify: Option<Arc<OutboundPipeNotify>>,
    },
    Buffered(Vec<T>),
    Empty,
    Inbound(Arc<InboundPipe>),
    InboundActive(SubpathReader),
    InboundPolling,
}

/// Consumer half of a WIT `stream<T>`.
pub struct StreamReader<T> {
    state: StreamReaderState<T>,
    decoder: Option<Arc<dyn InboundDecoder<T>>>,
    buffered: VecDeque<T>,
    poll_fut: Option<StreamPollFuture<T>>,
}

impl<T> Unpin for StreamReader<T> {}

impl<T> std::fmt::Debug for StreamReader<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamReader").finish()
    }
}

impl<T> Drop for StreamReader<T> {
    fn drop(&mut self) {
        match &mut self.state {
            StreamReaderState::Outbound(Some(pipe)) => pipe.mark_reader_dropped(),
            StreamReaderState::OutboundMapped {
                notify: Some(notify),
                ..
            } => notify.mark_reader_dropped(),
            _ => {}
        }
    }
}

impl<T> StreamReader<T> {
    /// Creates an immediately-closed empty stream.
    pub fn empty() -> Self {
        Self {
            state: StreamReaderState::Empty,
            decoder: None,
            buffered: VecDeque::new(),
            poll_fut: None,
        }
    }

    /// Creates a finite stream backed by `items`, delivered lazily according to
    /// receiver credits once sent over RPC.
    pub fn from_vec(items: Vec<T>) -> Self {
        if items.is_empty() {
            return Self::empty();
        }
        Self {
            state: StreamReaderState::Buffered(items),
            decoder: None,
            buffered: VecDeque::new(),
            poll_fut: None,
        }
    }
}

impl<T: MaybeSend + 'static> StreamReader<T> {
    /// Maps an outbound server-side `StreamReader<T>` into its wire element
    /// adapter `StreamReader<U>` before encoding onto an invocation.
    #[doc(hidden)]
    pub fn __map_outbound<U: MaybeSend + 'static>(mut self, map: fn(T) -> U) -> StreamReader<U> {
        let state = match std::mem::replace(&mut self.state, StreamReaderState::Empty) {
            StreamReaderState::Outbound(Some(pipe)) => {
                let notify = pipe.drop_notify();
                let slot: Box<dyn OutboundSlot<T>> = Box::new(PipeOutboundSlot::new(pipe));
                StreamReaderState::OutboundMapped {
                    slot: Some(Box::new(MappedOutboundSlot::new(slot, map))),
                    notify: Some(notify),
                }
            }
            StreamReaderState::Outbound(None) => StreamReaderState::OutboundMapped {
                slot: None,
                notify: None,
            },
            StreamReaderState::OutboundMapped { slot, notify } => {
                StreamReaderState::OutboundMapped {
                    slot: slot.map(|s| Box::new(MappedOutboundSlot::new(s, map)) as _),
                    notify,
                }
            }
            StreamReaderState::Buffered(items) => {
                StreamReaderState::Buffered(items.into_iter().map(map).collect())
            }
            StreamReaderState::Empty => StreamReaderState::Empty,
            StreamReaderState::Inbound(pipe) => StreamReaderState::Inbound(pipe),
            StreamReaderState::InboundActive(reader) => StreamReaderState::InboundActive(reader),
            StreamReaderState::InboundPolling => StreamReaderState::InboundPolling,
        };
        let decoder = self
            .decoder
            .take()
            .map(|dec| Arc::new(MappedInboundDecoder::new(dec, map)) as Arc<dyn InboundDecoder<U>>);
        let buffered = std::mem::take(&mut self.buffered)
            .into_iter()
            .map(map)
            .collect();
        StreamReader {
            state,
            decoder,
            buffered,
            poll_fut: None,
        }
    }

    /// Maps an inbound server-side wire `StreamReader<T>` into its handler
    /// element type `StreamReader<U>` after decoding from an invocation.
    #[doc(hidden)]
    pub fn __map_inbound<U: MaybeSend + 'static>(self, map: fn(T) -> U) -> StreamReader<U> {
        self.__map_outbound(map)
    }

    pub(crate) fn encode_into_subpath<R: ResourceEntry>(
        mut self,
        enc: &mut Encoder<'_, R>,
    ) -> Result<(), WireError>
    where
        T: RpcEncode<R>,
    {
        let sub_id = enc.alloc_subpath_id()?;
        enc.write_u32(sub_id);
        let encoder: Arc<dyn OutboundEncoder<T>> = Arc::new(TableOutboundEncoder::<T, R>::new(
            enc.resource_table().cloned(),
            enc.spawner().cloned(),
        ));
        match &mut self.state {
            StreamReaderState::Outbound(slot) => {
                let pipe = slot.take().ok_or_else(|| WireError::MalformedPayload {
                    context: "StreamReader::encode".to_owned(),
                    detail: "stream reader already consumed".to_owned(),
                })?;
                enc.push_outbound_subpath(PendingOutboundSubpath::live(
                    sub_id,
                    Box::new(DirectPipeBinder::new(pipe, encoder)),
                ));
            }
            StreamReaderState::OutboundMapped { slot, notify } => {
                let bound_slot = slot.take().ok_or_else(|| WireError::MalformedPayload {
                    context: "StreamReader::encode".to_owned(),
                    detail: "mapped stream reader already consumed".to_owned(),
                })?;
                let _ = notify.take();
                enc.push_outbound_subpath(PendingOutboundSubpath::live(
                    sub_id,
                    Box::new(BoundSlotBinder::new(bound_slot, encoder)),
                ));
            }
            StreamReaderState::Buffered(items) => {
                let drained = std::mem::take(items);
                if T::CONTAINS_RESOURCES
                    && enc.resource_table().is_some()
                    && let Some(spawner) = enc.spawner().cloned()
                {
                    let cancel = Arc::new(SubpathCancelToken::new());
                    enc.push_outbound_subpath(PendingOutboundSubpath::pumped(
                        sub_id,
                        spawner,
                        cancel,
                        Box::new(StreamItemsPump {
                            items: drained,
                            encoder,
                        }),
                    ));
                } else {
                    let mut frames = VecDeque::with_capacity(drained.len());
                    for item in drained {
                        let bytes = enc.encode_nested_frame(|item_enc| {
                            T::rpc_encode_vec(vec![item], item_enc)
                        })?;
                        frames.push_back(bytes);
                    }
                    enc.push_outbound_subpath(PendingOutboundSubpath::buffered(sub_id, frames));
                }
            }
            StreamReaderState::Empty => {
                enc.push_outbound_subpath(PendingOutboundSubpath::empty(sub_id));
            }
            StreamReaderState::Inbound(_)
            | StreamReaderState::InboundActive(_)
            | StreamReaderState::InboundPolling => {
                return Err(WireError::MalformedPayload {
                    context: "StreamReader::encode".to_owned(),
                    detail: "inbound stream reader must be forwarded explicitly".to_owned(),
                });
            }
        }
        Ok(())
    }

    pub(crate) fn decode_from_subpath<R: ResourceEntry>(
        dec: &mut Decoder<'_, R>,
    ) -> Result<Self, WireError>
    where
        T: RpcDecode<R>,
    {
        let sub_id = dec.read_u32()?;
        if sub_id == 0 {
            return Err(WireError::MalformedPayload {
                context: "StreamReader::decode".to_owned(),
                detail: "invalid zero stream sub-path id".to_owned(),
            });
        }
        let pipe = Arc::new(InboundPipe::new());
        let decoder: Arc<dyn InboundDecoder<T>> = Arc::new(TableInboundDecoder::<T, R>::new(
            dec.resource_table().cloned(),
            dec.spawner().cloned(),
        ));
        dec.push_inbound_subpath(PendingInboundSubpath {
            sub_id,
            credit_mode: SubpathCreditMode::Streaming {
                window: dec.default_stream_window(),
            },
            pipe: Arc::clone(&pipe),
        });
        Ok(Self {
            state: StreamReaderState::Inbound(pipe),
            decoder: Some(decoder),
            buffered: VecDeque::new(),
            poll_fut: None,
        })
    }

    /// Reads the next single item from the stream, replenishing credit to the
    /// remote producer when a batch frame is consumed.
    pub async fn next(&mut self) -> Result<Option<T>, RpcError> {
        loop {
            if let Some(item) = self.buffered.pop_front() {
                return Ok(Some(item));
            }
            match self.next_frame_batch().await? {
                Some(batch) => {
                    self.buffered.extend(batch);
                }
                None => return Ok(None),
            }
        }
    }

    /// Reads the next non-empty batch of items from the stream.
    pub async fn next_batch(&mut self) -> Result<Option<Vec<T>>, RpcError> {
        if !self.buffered.is_empty() {
            return Ok(Some(self.buffered.drain(..).collect()));
        }
        self.next_frame_batch().await
    }

    /// Drains all remaining items on the stream into a `Vec<T>`.
    pub async fn collect_all(mut self) -> Result<Vec<T>, RpcError> {
        let mut all = Vec::new();
        while let Some(batch) = self.next_batch().await? {
            all.extend(batch);
        }
        Ok(all)
    }

    async fn next_frame_batch(&mut self) -> Result<Option<Vec<T>>, RpcError> {
        if let StreamReaderState::Inbound(pipe) = &self.state {
            let pipe = Arc::clone(pipe);
            match pipe.take_reader().await {
                Some(reader) => {
                    self.state = StreamReaderState::InboundActive(reader);
                }
                None => {
                    self.state = StreamReaderState::Empty;
                    return Ok(None);
                }
            }
        }

        match &mut self.state {
            StreamReaderState::Empty | StreamReaderState::InboundPolling => Ok(None),
            StreamReaderState::Buffered(items) => {
                if items.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(std::mem::take(items)))
                }
            }
            StreamReaderState::Outbound(_) | StreamReaderState::OutboundMapped { .. } => {
                Err(RpcError::StreamClosed)
            }
            StreamReaderState::InboundActive(reader) => {
                let decoder = self.decoder.as_ref().ok_or(RpcError::StreamClosed)?;
                recv_stream_batch_from_reader(reader, decoder.as_ref()).await
            }
            StreamReaderState::Inbound(_) => unreachable!("inbound pipe transitioned above"),
        }
    }
}

async fn recv_stream_batch_from_reader<T: 'static>(
    reader: &mut SubpathReader,
    decoder: &dyn InboundDecoder<T>,
) -> Result<Option<Vec<T>>, RpcError> {
    loop {
        let Some(chunk) = reader.recv().await? else {
            return Ok(None);
        };
        let peer = reader.peer();
        let call = reader.call_handle();

        let (batch, subpaths) = decoder.decode_batch(&chunk, peer).resolve().await?;
        activate_inbound_subpaths(&call, subpaths).await?;
        if !batch.is_empty() {
            return Ok(Some(batch));
        }
    }
}

impl<T: MaybeSend + 'static> Stream for StreamReader<T> {
    type Item = Result<T, RpcError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            if let Some(item) = this.buffered.pop_front() {
                return Poll::Ready(Some(Ok(item)));
            }

            if this.poll_fut.is_none() {
                match std::mem::replace(&mut this.state, StreamReaderState::InboundPolling) {
                    StreamReaderState::Empty => {
                        this.state = StreamReaderState::Empty;
                        return Poll::Ready(None);
                    }
                    StreamReaderState::Buffered(items) => {
                        if items.is_empty() {
                            this.state = StreamReaderState::Empty;
                            return Poll::Ready(None);
                        }
                        this.state = StreamReaderState::Empty;
                        this.buffered.extend(items);
                        continue;
                    }
                    StreamReaderState::Outbound(pipe) => {
                        this.state = StreamReaderState::Outbound(pipe);
                        return Poll::Ready(Some(Err(RpcError::StreamClosed)));
                    }
                    StreamReaderState::OutboundMapped { slot, notify } => {
                        this.state = StreamReaderState::OutboundMapped { slot, notify };
                        return Poll::Ready(Some(Err(RpcError::StreamClosed)));
                    }
                    StreamReaderState::Inbound(pipe) => {
                        let Some(decoder) = this.decoder.clone() else {
                            this.state = StreamReaderState::Empty;
                            return Poll::Ready(Some(Err(RpcError::StreamClosed)));
                        };
                        this.poll_fut = Some(Box::pin(async move {
                            let Some(mut reader) = pipe.take_reader().await else {
                                return (None, Ok(None));
                            };
                            let res =
                                recv_stream_batch_from_reader(&mut reader, decoder.as_ref()).await;
                            (Some(reader), res)
                        }));
                    }
                    StreamReaderState::InboundActive(mut reader) => {
                        let Some(decoder) = this.decoder.clone() else {
                            this.state = StreamReaderState::Empty;
                            return Poll::Ready(Some(Err(RpcError::StreamClosed)));
                        };
                        this.poll_fut = Some(Box::pin(async move {
                            let res =
                                recv_stream_batch_from_reader(&mut reader, decoder.as_ref()).await;
                            (Some(reader), res)
                        }));
                    }
                    StreamReaderState::InboundPolling => {
                        this.state = StreamReaderState::Empty;
                        return Poll::Ready(None);
                    }
                }
            }

            let fut = this
                .poll_fut
                .as_mut()
                .expect("stream poll future must exist");
            match fut.as_mut().poll(cx) {
                Poll::Ready((reader_back, res)) => {
                    this.poll_fut = None;
                    this.state = match reader_back {
                        Some(reader) => StreamReaderState::InboundActive(reader),
                        None => StreamReaderState::Empty,
                    };
                    match res {
                        Ok(Some(batch)) => {
                            this.buffered.extend(batch);
                        }
                        Ok(None) => return Poll::Ready(None),
                        Err(err) => return Poll::Ready(Some(Err(err))),
                    }
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

/// Completer half of a single-shot WIT `future<T>`.
pub struct FutureWriter<T> {
    pipe: Arc<OutboundPipe<T>>,
    bound: Option<(SubpathWriter, Arc<dyn OutboundEncoder<T>>)>,
    resolved: bool,
}

impl<T> std::fmt::Debug for FutureWriter<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FutureWriter")
            .field("resolved", &self.resolved)
            .finish()
    }
}

impl<T> Drop for FutureWriter<T> {
    fn drop(&mut self) {
        if !self.resolved {
            let _ = self.bound.take();
            self.pipe.mark_writer_dropped();
        }
    }
}

impl<T: MaybeSend + 'static> FutureWriter<T> {
    /// Resolves the remote [`FutureReader`] with `value` and closes the
    /// sub-path.
    pub async fn resolve(mut self, value: T) -> Result<(), RpcError> {
        self.resolved = true;
        if self.pipe.is_closed_for_writer() {
            return Err(RpcError::Cancelled);
        }
        let (mut writer, encoder) = if let Some(bound) = self.bound.take() {
            bound
        } else {
            self.pipe
                .wait_until_bound()
                .await
                .map_err(|_| RpcError::Cancelled)?;
            self.pipe.take_bound().await.ok_or(RpcError::Cancelled)?
        };
        if writer.is_peer_stopped() {
            return Err(RpcError::Cancelled);
        }

        let call = writer.call_handle();
        let encoded = encoder.encode_one(&call, value).resolve().await?;
        let mut guard = SendRollbackGuard::new(encoded.rollback);
        let cancels = activate_outbound_subpaths_tracked(&call, encoded.subpaths).await;
        guard.add_cancels(cancels);

        match writer.send(encoded.bytes).await {
            Ok(()) => {
                // Frame is on the wire; peer can decode it even before `Close`.
                guard.disarm();
            }
            Err(err) => {
                guard.rollback_now().await;
                return Err(match err.wire_error() {
                    Some(wire) => RpcError::Wire(wire.clone()),
                    None => RpcError::Cancelled,
                });
            }
        }
        writer.close().await?;
        Ok(())
    }

    /// Whether the remote consumer dropped its [`FutureReader`] or cancelled
    /// the invocation.
    pub async fn is_cancelled(&self) -> bool {
        if self.pipe.is_closed_for_writer() {
            return true;
        }
        if let Some((writer, _)) = self.bound.as_ref() {
            return writer.is_peer_stopped();
        }
        self.pipe.is_peer_stopped().await
    }

    /// Waits until the remote consumer cancels or drops its [`FutureReader`].
    pub async fn cancelled(&self) {
        if let Some((writer, _)) = self.bound.as_ref() {
            writer.wait_peer_stopped().await;
            return;
        }
        if self.pipe.wait_until_bound().await.is_err() {
            return;
        }
        if let Some(stop_watch) = self.pipe.stop_watch().await {
            stop_watch.wait_peer_stopped().await;
        }
    }
}

struct FutureValuePump<T> {
    value: T,
    encoder: Arc<dyn OutboundEncoder<T>>,
}

impl<T: MaybeSend + 'static> PendingOutboundPump for FutureValuePump<T> {
    fn into_task(
        self: Box<Self>,
        mut writer: SubpathWriter,
        cancel: Arc<SubpathCancelToken>,
    ) -> SubpathTask {
        let Self { value, encoder } = *self;
        Box::pin(async move {
            if cancel.is_cancelled() || writer.is_peer_stopped() {
                return;
            }
            let call = writer.call_handle();
            let encoded = match encoder.encode_one(&call, value).resolve().await {
                Ok(encoded) => encoded,
                Err(_) => return,
            };
            let mut guard = SendRollbackGuard::new(encoded.rollback);
            let cancels = activate_outbound_subpaths_tracked(&call, encoded.subpaths).await;
            guard.add_cancels(cancels);

            let send_res =
                futures_lite::future::or(async { Some(writer.send(encoded.bytes).await) }, async {
                    cancel.wait().await;
                    None
                })
                .await;
            match send_res {
                Some(Ok(())) => {
                    guard.disarm();
                    let _ = writer.close().await;
                }
                Some(Err(_)) | None => {
                    guard.rollback_now().await;
                }
            }
        })
    }
}

enum FutureReaderState<T> {
    Outbound(Option<Arc<OutboundPipe<T>>>),
    OutboundMapped {
        slot: Option<Box<dyn OutboundSlot<T>>>,
        notify: Option<Arc<OutboundPipeNotify>>,
    },
    Ready(Option<T>),
    Inbound(Arc<InboundPipe>),
}

/// Consumer half of a single-shot WIT `future<T>`.
///
/// Directly awaits to `Result<T, RpcError>`; dropping before resolution
/// propagates cancellation on the sub-path to the remote [`FutureWriter`].
pub struct FutureReader<T> {
    state: FutureReaderState<T>,
    decoder: Option<Arc<dyn InboundDecoder<T>>>,
    poll_fut: Option<FuturePollFuture<T>>,
}

impl<T> Unpin for FutureReader<T> {}

impl<T> std::fmt::Debug for FutureReader<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FutureReader").finish()
    }
}

impl<T> Drop for FutureReader<T> {
    fn drop(&mut self) {
        match &mut self.state {
            FutureReaderState::Outbound(Some(pipe)) => pipe.mark_reader_dropped(),
            FutureReaderState::OutboundMapped {
                notify: Some(notify),
                ..
            } => notify.mark_reader_dropped(),
            _ => {}
        }
    }
}

impl<T> FutureReader<T> {
    /// Constructs an immediately-resolved `FutureReader` without needing a
    /// separate background task to drive [`FutureWriter`].
    pub fn ready(value: T) -> Self {
        Self {
            state: FutureReaderState::Ready(Some(value)),
            decoder: None,
            poll_fut: None,
        }
    }
}

impl<T: MaybeSend + 'static> FutureReader<T> {
    /// Maps an outbound server-side `FutureReader<T>` into its wire element
    /// adapter `FutureReader<U>` before encoding onto an invocation.
    #[doc(hidden)]
    pub fn __map_outbound<U: MaybeSend + 'static>(mut self, map: fn(T) -> U) -> FutureReader<U> {
        let state = match std::mem::replace(&mut self.state, FutureReaderState::Ready(None)) {
            FutureReaderState::Outbound(Some(pipe)) => {
                let notify = pipe.drop_notify();
                let slot: Box<dyn OutboundSlot<T>> = Box::new(PipeOutboundSlot::new(pipe));
                FutureReaderState::OutboundMapped {
                    slot: Some(Box::new(MappedOutboundSlot::new(slot, map))),
                    notify: Some(notify),
                }
            }
            FutureReaderState::Outbound(None) => FutureReaderState::OutboundMapped {
                slot: None,
                notify: None,
            },
            FutureReaderState::OutboundMapped { slot, notify } => {
                FutureReaderState::OutboundMapped {
                    slot: slot.map(|s| Box::new(MappedOutboundSlot::new(s, map)) as _),
                    notify,
                }
            }
            FutureReaderState::Ready(slot) => FutureReaderState::Ready(slot.map(map)),
            FutureReaderState::Inbound(pipe) => FutureReaderState::Inbound(pipe),
        };
        let decoder = self
            .decoder
            .take()
            .map(|dec| Arc::new(MappedInboundDecoder::new(dec, map)) as Arc<dyn InboundDecoder<U>>);
        FutureReader {
            state,
            decoder,
            poll_fut: None,
        }
    }

    /// Maps an inbound server-side wire `FutureReader<T>` into its handler
    /// element type `FutureReader<U>` after decoding from an invocation.
    #[doc(hidden)]
    pub fn __map_inbound<U: MaybeSend + 'static>(self, map: fn(T) -> U) -> FutureReader<U> {
        self.__map_outbound(map)
    }

    pub(crate) fn encode_into_subpath<R: ResourceEntry>(
        mut self,
        enc: &mut Encoder<'_, R>,
    ) -> Result<(), WireError>
    where
        T: RpcEncode<R>,
    {
        let sub_id = enc.alloc_subpath_id()?;
        enc.write_u32(sub_id);
        let encoder: Arc<dyn OutboundEncoder<T>> = Arc::new(TableOutboundEncoder::<T, R>::new(
            enc.resource_table().cloned(),
            enc.spawner().cloned(),
        ));
        match &mut self.state {
            FutureReaderState::Outbound(slot) => {
                let pipe = slot.take().ok_or_else(|| WireError::MalformedPayload {
                    context: "FutureReader::encode".to_owned(),
                    detail: "future reader already consumed".to_owned(),
                })?;
                enc.push_outbound_subpath(PendingOutboundSubpath::live(
                    sub_id,
                    Box::new(DirectPipeBinder::new(pipe, encoder)),
                ));
            }
            FutureReaderState::OutboundMapped { slot, notify } => {
                let bound_slot = slot.take().ok_or_else(|| WireError::MalformedPayload {
                    context: "FutureReader::encode".to_owned(),
                    detail: "mapped future reader already consumed".to_owned(),
                })?;
                let _ = notify.take();
                enc.push_outbound_subpath(PendingOutboundSubpath::live(
                    sub_id,
                    Box::new(BoundSlotBinder::new(bound_slot, encoder)),
                ));
            }
            FutureReaderState::Ready(slot) => {
                let value = slot.take().ok_or_else(|| WireError::MalformedPayload {
                    context: "FutureReader::encode".to_owned(),
                    detail: "ready future reader already consumed".to_owned(),
                })?;
                if T::CONTAINS_RESOURCES
                    && enc.resource_table().is_some()
                    && let Some(spawner) = enc.spawner().cloned()
                {
                    let cancel = Arc::new(SubpathCancelToken::new());
                    enc.push_outbound_subpath(PendingOutboundSubpath::pumped(
                        sub_id,
                        spawner,
                        cancel,
                        Box::new(FutureValuePump { value, encoder }),
                    ));
                } else {
                    let payload = enc.encode_nested_frame(|val_enc| value.rpc_encode(val_enc))?;
                    let mut frames = VecDeque::with_capacity(1);
                    frames.push_back(payload);
                    enc.push_outbound_subpath(PendingOutboundSubpath::buffered(sub_id, frames));
                }
            }
            FutureReaderState::Inbound(_) => {
                return Err(WireError::MalformedPayload {
                    context: "FutureReader::encode".to_owned(),
                    detail: "inbound future reader must be awaited and re-wrapped explicitly"
                        .to_owned(),
                });
            }
        }
        Ok(())
    }

    pub(crate) fn decode_from_subpath<R: ResourceEntry>(
        dec: &mut Decoder<'_, R>,
    ) -> Result<Self, WireError>
    where
        T: RpcDecode<R>,
    {
        let sub_id = dec.read_u32()?;
        if sub_id == 0 {
            return Err(WireError::MalformedPayload {
                context: "FutureReader::decode".to_owned(),
                detail: "invalid zero future sub-path id".to_owned(),
            });
        }
        let pipe = Arc::new(InboundPipe::new());
        let decoder: Arc<dyn InboundDecoder<T>> = Arc::new(TableInboundDecoder::<T, R>::new(
            dec.resource_table().cloned(),
            dec.spawner().cloned(),
        ));
        dec.push_inbound_subpath(PendingInboundSubpath {
            sub_id,
            credit_mode: SubpathCreditMode::Oneshot,
            pipe: Arc::clone(&pipe),
        });
        Ok(Self {
            state: FutureReaderState::Inbound(pipe),
            decoder: Some(decoder),
            poll_fut: None,
        })
    }
}

async fn recv_future_value<T: 'static>(
    pipe: Arc<InboundPipe>,
    decoder: Arc<dyn InboundDecoder<T>>,
) -> Result<T, RpcError> {
    let Some(mut reader) = pipe.take_reader().await else {
        return Err(RpcError::FutureDropped);
    };
    let Some(bytes) = reader.recv().await? else {
        return Err(RpcError::FutureDropped);
    };
    let peer = reader.peer();
    let call = reader.call_handle();
    drop(reader);

    let (value, subpaths) = decoder.decode_one(&bytes, peer).resolve().await?;
    activate_inbound_subpaths(&call, subpaths).await?;
    Ok(value)
}

impl<T: MaybeSend + 'static> Future for FutureReader<T> {
    type Output = Result<T, RpcError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.poll_fut.is_none() {
            match &mut this.state {
                FutureReaderState::Ready(slot) => {
                    return match slot.take() {
                        Some(val) => Poll::Ready(Ok(val)),
                        None => Poll::Ready(Err(RpcError::FutureDropped)),
                    };
                }
                FutureReaderState::Outbound(_) | FutureReaderState::OutboundMapped { .. } => {
                    return Poll::Ready(Err(RpcError::FutureDropped));
                }
                FutureReaderState::Inbound(pipe) => {
                    let Some(decoder) = this.decoder.clone() else {
                        return Poll::Ready(Err(RpcError::FutureDropped));
                    };
                    let pipe = Arc::clone(pipe);
                    this.poll_fut = Some(Box::pin(recv_future_value(pipe, decoder)));
                }
            }
        }

        let fut = this
            .poll_fut
            .as_mut()
            .expect("future reader poll state must exist");
        fut.as_mut().poll(cx)
    }
}
