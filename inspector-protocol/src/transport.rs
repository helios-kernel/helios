use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::task::{Context, Poll};

use async_channel::{Receiver, Sender};
use async_lock::Mutex;
use bytes::Bytes;
use event_listener::{Event, EventListener};
use futures_core::Stream;
use futures_io::{AsyncRead as FuturesAsyncRead, AsyncWrite as FuturesAsyncWrite};
#[cfg(feature = "host")]
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::error::{TransportError, WireError};
use crate::wire::{Frame, read_frame, write_frame};

/// Transport-level result with structured error provenance.
///
/// Every caller of this transport — the inspector, the guest services and
/// this crate's own tests — uses this alias, so a failure keeps the
/// variant that names what the transport was doing.
pub type Result<T> = core::result::Result<T, TransportError>;

type IoFuture<T> = Pin<Box<dyn Future<Output = io::Result<T>> + Send + 'static>>;
type ServeFuture = Pin<Box<dyn Future<Output = Result<()>> + Send + 'static>>;
type InvocationAccept<R, W> = Result<((), Outgoing<R, W>, Incoming<R, W>)>;
pub(crate) const RAW_UPLOAD_CHUNK_BYTES: usize = 64 * 1024;

/// Most undelivered inbound payload bytes one invocation holds before the
/// peer is failed for it.
pub const MAX_UNDELIVERED_BYTES: usize = 256 * RAW_UPLOAD_CHUNK_BYTES;

/// Most distinct paths one invocation holds inbound state for.
///
/// Lifted from `1` so concurrent `stream<T>` and `future<T>` sub-paths run
/// on a single invocation while still bounding per-invocation path state.
pub const MAX_INBOUND_PATHS: usize = 64;

/// Lock-free broadcast progress signal implementing arm-before-test wakeups
/// without `std::sync::Mutex` or runtime-specific primitives.
#[derive(Default)]
pub(crate) struct Progress {
    generation: AtomicU64,
    event: Event,
}

impl Progress {
    pub(crate) fn new() -> Self {
        Self {
            generation: AtomicU64::new(0),
            event: Event::new(),
        }
    }

    pub(crate) fn mark(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    pub(crate) async fn changed(&self, mark: u64) {
        let mut listener: Option<EventListener> = None;
        std::future::poll_fn(|cx| {
            loop {
                if self.generation.load(Ordering::Acquire) != mark {
                    return Poll::Ready(());
                }
                if listener.is_none() {
                    listener = Some(self.event.listen());
                    continue;
                }
                let active = listener
                    .as_mut()
                    .expect("progress listener must exist while parked");
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

    pub(crate) fn signal(&self) {
        self.generation.fetch_add(1, Ordering::AcqRel);
        self.event.notify(usize::MAX);
    }
}

/// How an invocation failed, kept typed until a waiter observes it as an
/// `io::Error` or [`TransportError`].
pub(crate) enum Fault {
    Remote(String),
    Wire(WireError),
}

impl Fault {
    pub(crate) fn to_io(&self) -> io::Error {
        match self {
            Self::Remote(message) => io::Error::other(message.clone()),
            Self::Wire(error) => error.clone().into(),
        }
    }

    pub(crate) fn to_transport(&self) -> TransportError {
        match self {
            Self::Remote(message) => TransportError::Rejected(message.clone()),
            Self::Wire(error) => TransportError::Wire(error.clone()),
        }
    }
}

#[derive(Default)]
pub(crate) struct InboundBuffers {
    pub(crate) chunks: HashMap<Vec<usize>, VecDeque<Bytes>>,
    pub(crate) closed: HashSet<Vec<usize>>,
    pub(crate) credits: HashMap<Vec<usize>, u32>,
    pub(crate) undelivered_bytes: usize,
    pub(crate) error: Option<Fault>,
}

impl InboundBuffers {
    fn admits_path(&self, path: &[usize]) -> bool {
        if self.chunks.contains_key(path)
            || self.closed.contains(path)
            || self.credits.contains_key(path)
        {
            return true;
        }
        let mut distinct = self.chunks.len();
        for closed in &self.closed {
            if !self.chunks.contains_key(closed.as_slice()) {
                distinct += 1;
            }
        }
        for credited in self.credits.keys() {
            if !self.chunks.contains_key(credited.as_slice())
                && !self.closed.contains(credited.as_slice())
            {
                distinct += 1;
            }
        }
        distinct < MAX_INBOUND_PATHS
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

enum InvocationOwner<R, W> {
    Client(Weak<ClientInner<R, W>>),
    Server(Weak<ServerInner<R, W>>),
}

/// One call in flight, and the only place its answer is ever filed.
pub struct Invocation<R, W> {
    id: u32,
    owner: InvocationOwner<R, W>,
    pub(crate) inbound: Mutex<InboundBuffers>,
    outbound_credits: Mutex<HashMap<Vec<usize>, u32>>,
    accepted: AtomicBool,
    cancelled: AtomicBool,
    reply: Mutex<Option<Reply>>,
    progress: Progress,
}

pub struct Client<R, W> {
    inner: Arc<ClientInner<R, W>>,
    lifetime: Sender<()>,
}

impl<R, W> Clone for Client<R, W> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            lifetime: self.lifetime.clone(),
        }
    }
}

struct ClientInner<R, W> {
    transport: Mutex<Option<ClientTransport<R, W>>>,
    outgoing: Sender<PendingFrame>,
    control: Sender<Frame>,
    closed: AtomicBool,
    driver_progress: Progress,
    next_invocation: AtomicU32,
    active: Mutex<HashMap<u32, Weak<Invocation<R, W>>>>,
}

struct ClientTransport<R, W> {
    read: R,
    write: W,
    outgoing: Receiver<PendingFrame>,
    control: Receiver<Frame>,
    lifetime: Receiver<()>,
}

struct PendingFrame {
    frame: Frame,
    completion: Sender<io::Result<()>>,
}

struct ClientDriverGuard<R, W>(Arc<ClientInner<R, W>>);

impl<R, W> Drop for ClientDriverGuard<R, W> {
    fn drop(&mut self) {
        self.0.closed.store(true, Ordering::Release);
        self.0.driver_progress.signal();
    }
}

#[derive(Clone)]
pub struct Server<R, W> {
    inner: Arc<ServerInner<R, W>>,
}

type MethodKey = (String, String);
type DispatchMap<R, W> = HashMap<MethodKey, Registration<R, W>>;

struct ServerInner<R, W> {
    read: Arc<Mutex<R>>,
    write: Arc<Mutex<W>>,
    dispatch: Arc<Mutex<DispatchMap<R, W>>>,
    register_tx: Sender<(MethodKey, Registration<R, W>)>,
    register_rx: Receiver<(MethodKey, Registration<R, W>)>,
    active: Mutex<HashMap<u32, Weak<Invocation<R, W>>>>,
    closed: AtomicBool,
}

struct Registration<R, W> {
    tx: Sender<InvocationAccept<R, W>>,
}

impl<R, W> Clone for Registration<R, W> {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
        }
    }
}

enum Reply {
    Accept,
    Reject(String),
    Fault(WireError),
}

/// RAII cancellation guard for an in-flight client invocation.
///
/// Dropping this guard before [`Self::disarm`] sends a root `Frame::Close`
/// (`path: []`) so the peer cancels its running handler task.
pub struct InvocationCancelGuard {
    invocation: u32,
    control: Option<Sender<Frame>>,
}

impl InvocationCancelGuard {
    pub fn disarm(&mut self) {
        self.control = None;
    }
}

impl Drop for InvocationCancelGuard {
    fn drop(&mut self) {
        if let Some(control) = self.control.take() {
            let _ = control.try_send(Frame::Close {
                invocation: self.invocation,
                path: Vec::new(),
            });
        }
    }
}

pub struct Incoming<R, W> {
    pub(crate) invocation: Arc<Invocation<R, W>>,
    path: Arc<[usize]>,
    credit_gated: bool,
    current: Option<Bytes>,
    pending: Option<IoFuture<Option<Bytes>>>,
    eof: bool,
}

pub struct Outgoing<R, W> {
    invocation: Arc<Invocation<R, W>>,
    path: Arc<[usize]>,
    credit_gated: bool,
    pending_write: Option<(usize, IoFuture<()>)>,
    pending_close: Option<IoFuture<()>>,
    closed: bool,
}

pub struct InvocationStream<R, W> {
    server: Arc<ServerInner<R, W>>,
    rx: Pin<Box<Receiver<InvocationAccept<R, W>>>>,
    pending: Option<ServeFuture>,
}

enum EitherClientFrame {
    Control(Frame),
    Data(PendingFrame),
}

impl<R, W> Client<R, W>
where
    R: FuturesAsyncRead + Send + Unpin + 'static,
    W: FuturesAsyncWrite + Send + Unpin + 'static,
{
    pub fn new(read: R, write: W) -> Self {
        let (outgoing, incoming) = async_channel::bounded(1);
        let (control, control_rx) = async_channel::unbounded();
        let (lifetime, ended) = async_channel::bounded(1);
        Self {
            inner: Arc::new(ClientInner {
                transport: Mutex::new(Some(ClientTransport {
                    read,
                    write,
                    outgoing: incoming,
                    control: control_rx,
                    lifetime: ended,
                })),
                outgoing,
                control,
                closed: AtomicBool::new(false),
                driver_progress: Progress::new(),
                next_invocation: AtomicU32::new(1),
                active: Mutex::new(HashMap::new()),
            }),
            lifetime,
        }
    }

    pub async fn route_frames(self) -> Result<()> {
        let Self { inner, lifetime } = self;
        drop(lifetime);
        let transport = inner.transport.lock().await.take().ok_or_else(|| {
            TransportError::io(
                "start connection driver",
                io::Error::other("client connection driver already started"),
            )
        })?;
        let _guard = ClientDriverGuard(inner.clone());
        let ClientTransport {
            mut read,
            mut write,
            outgoing,
            control,
            lifetime,
        } = transport;
        let receive = async {
            loop {
                let Some(frame) = read_frame(&mut read)
                    .await
                    .map_err(|source| TransportError::io("read client frame", source))?
                else {
                    return Ok(());
                };
                route_client_frame(&inner, frame)
                    .await
                    .map_err(|source| TransportError::io("route client frame", source))?;
            }
        };
        let transmit = async {
            loop {
                while let Ok(frame) = control.try_recv() {
                    write_frame(&mut write, &frame).await.map_err(|source| {
                        TransportError::io("write client control frame", source)
                    })?;
                }
                let next = futures_lite::future::or(
                    async { control.recv().await.ok().map(EitherClientFrame::Control) },
                    async { outgoing.recv().await.ok().map(EitherClientFrame::Data) },
                )
                .await;
                match next {
                    Some(EitherClientFrame::Control(frame)) => {
                        write_frame(&mut write, &frame).await.map_err(|source| {
                            TransportError::io("write client control frame", source)
                        })?;
                    }
                    Some(EitherClientFrame::Data(pending)) => {
                        match write_frame(&mut write, &pending.frame).await {
                            Ok(()) => {
                                let _ = pending.completion.try_send(Ok(()));
                            }
                            Err(source) => {
                                let message = source.to_string();
                                let _ = pending.completion.try_send(Err(source));
                                return Err(TransportError::io(
                                    "write client frame",
                                    io::Error::other(message),
                                ));
                            }
                        }
                    }
                    None => return Ok(()),
                }
            }
        };
        let stopped = async {
            let _ = lifetime.recv().await;
            Ok(())
        };
        let result =
            futures_lite::future::or(stopped, futures_lite::future::or(receive, transmit)).await;
        match &result {
            Ok(()) => close_client(&inner, "client connection driver stopped").await,
            Err(error) => close_client(&inner, &error.to_string()).await,
        }
        result
    }

    pub async fn invoke_raw(
        &self,
        instance: &str,
        func: &str,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let chunk_bytes = payload.len().max(1);
        self.invoke_raw_chunked(instance, func, payload, chunk_bytes)
            .await
    }

    pub async fn invoke_raw_chunked(
        &self,
        instance: &str,
        func: &str,
        payload: Vec<u8>,
        chunk_bytes: usize,
    ) -> Result<Vec<u8>> {
        let chunk_bytes = chunk_bytes.max(1);
        let (mut outgoing, mut incoming) =
            self.open_invocation(instance, func, Bytes::new()).await?;
        for chunk in payload.chunks(chunk_bytes) {
            futures_lite::io::AsyncWriteExt::write_all(&mut outgoing, chunk)
                .await
                .map_err(|source| TransportError::io("stream raw request payload", source))?;
        }
        futures_lite::io::AsyncWriteExt::close(&mut outgoing)
            .await
            .map_err(|source| TransportError::io("close raw request channel", source))?;
        let mut response = Vec::new();
        futures_lite::io::AsyncReadExt::read_to_end(&mut incoming, &mut response)
            .await
            .map_err(|source| TransportError::io("read raw response channel", source))?;
        Ok(response)
    }

    pub async fn invoke_raw_streaming(
        &self,
        instance: &str,
        func: &str,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>> {
        self.invoke_raw_chunked(instance, func, payload, RAW_UPLOAD_CHUNK_BYTES)
            .await
    }

    pub async fn open_invocation(
        &self,
        instance: &str,
        func: &str,
        params: Bytes,
    ) -> Result<(Outgoing<R, W>, Incoming<R, W>)> {
        let (mut guard, outgoing, incoming) = self
            .open_cancellable_invocation(instance, func, params)
            .await?;
        guard.disarm();
        Ok((outgoing, incoming))
    }

    pub async fn open_cancellable_invocation(
        &self,
        instance: &str,
        func: &str,
        params: Bytes,
    ) -> Result<(InvocationCancelGuard, Outgoing<R, W>, Incoming<R, W>)> {
        let id = self.inner.next_invocation.fetch_add(1, Ordering::Relaxed);
        let invocation = Invocation::new_client(id, &self.inner).await;
        enqueue_client_frame(
            &self.inner,
            Frame::Open {
                invocation: id,
                instance: instance.to_owned(),
                func: func.to_owned(),
            },
        )
        .await
        .map_err(|source| TransportError::io("open remote invocation", source))?;
        let mut guard = InvocationCancelGuard {
            invocation: id,
            control: Some(self.inner.control.clone()),
        };

        loop {
            let inv_mark = invocation.progress.mark();
            let drv_mark = self.inner.driver_progress.mark();

            if let Some(reply) = invocation.take_reply().await {
                match reply {
                    Reply::Accept => break,
                    Reply::Reject(message) => {
                        guard.disarm();
                        return Err(TransportError::Rejected(message));
                    }
                    Reply::Fault(error) => {
                        guard.disarm();
                        return Err(TransportError::Wire(error));
                    }
                }
            }
            if let Some(source) = invocation.failure().await {
                guard.disarm();
                return Err(TransportError::io("read remote invocation reply", source));
            }
            if self.inner.closed.load(Ordering::Acquire) {
                guard.disarm();
                return Err(TransportError::Closed);
            }
            futures_lite::future::or(
                invocation.progress.changed(inv_mark),
                self.inner.driver_progress.changed(drv_mark),
            )
            .await;
        }

        if !params.is_empty() {
            invocation
                .clone()
                .write_data(Vec::new(), params, false)
                .await
                .map_err(|source| TransportError::io("transmit synchronous parameters", source))?;
        }

        Ok((
            guard,
            Outgoing::root(invocation.clone()),
            Incoming::root(invocation),
        ))
    }
}

impl<R, W> Server<R, W>
where
    R: FuturesAsyncRead + Send + Unpin + 'static,
    W: FuturesAsyncWrite + Send + Unpin + 'static,
{
    pub fn new(read: R, write: W) -> Self {
        let (register_tx, register_rx) = async_channel::unbounded();
        Self {
            inner: Arc::new(ServerInner {
                read: Arc::new(Mutex::new(read)),
                write: Arc::new(Mutex::new(write)),
                dispatch: Arc::new(Mutex::new(HashMap::new())),
                register_tx,
                register_rx,
                active: Mutex::new(HashMap::new()),
                closed: AtomicBool::new(false),
            }),
        }
    }

    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::Acquire)
    }

    pub fn serve(&self, instance: &str, func: &str) -> Result<InvocationStream<R, W>> {
        let key = (instance.to_owned(), func.to_owned());
        let (tx, rx) = async_channel::bounded(8);
        self.inner
            .register_tx
            .try_send((key, Registration { tx }))
            .map_err(|_| TransportError::Closed)?;
        Ok(InvocationStream {
            server: self.inner.clone(),
            rx: Box::pin(rx),
            pending: None,
        })
    }
}

impl<R, W> Invocation<R, W> {
    async fn new_client(id: u32, inner: &Arc<ClientInner<R, W>>) -> Arc<Self> {
        let invocation = Arc::new(Self {
            id,
            owner: InvocationOwner::Client(Arc::downgrade(inner)),
            inbound: Mutex::new(InboundBuffers::default()),
            outbound_credits: Mutex::new(HashMap::new()),
            accepted: AtomicBool::new(false),
            cancelled: AtomicBool::new(false),
            reply: Mutex::new(None),
            progress: Progress::new(),
        });
        register_invocation(&inner.active, &invocation).await;
        invocation
    }

    async fn new_server(id: u32, inner: &Arc<ServerInner<R, W>>) -> Arc<Self> {
        let invocation = Arc::new(Self {
            id,
            owner: InvocationOwner::Server(Arc::downgrade(inner)),
            inbound: Mutex::new(InboundBuffers::default()),
            outbound_credits: Mutex::new(HashMap::new()),
            accepted: AtomicBool::new(true),
            cancelled: AtomicBool::new(false),
            reply: Mutex::new(None),
            progress: Progress::new(),
        });
        register_invocation(&inner.active, &invocation).await;
        invocation
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    pub async fn cancelled(&self) {
        loop {
            let mark = self.progress.mark();
            if self.is_cancelled() || self.failure().await.is_some() {
                return;
            }
            self.progress.changed(mark).await;
        }
    }

    async fn push_payload(&self, path: Vec<usize>, payload: Bytes) {
        {
            let mut inbound = self.inbound.lock().await;
            if inbound.error.is_some() {
                return;
            }
            let current_bytes = inbound.undelivered_bytes;
            if !inbound.admits_path(&path) {
                inbound.fail_wire(self.too_many_paths());
            } else if let Some(credits) = inbound.credits.get_mut(&path) {
                if *credits == 0 {
                    let wire_path = path
                        .iter()
                        .map(|&segment| u32::try_from(segment).unwrap_or(u32::MAX))
                        .collect();
                    inbound.fail_wire(WireError::StreamCreditExceeded {
                        invocation: self.id,
                        path: wire_path,
                    });
                } else if current_bytes + payload.len() > MAX_UNDELIVERED_BYTES {
                    let held = current_bytes + payload.len();
                    inbound.fail_wire(WireError::InboundBacklogExceeded {
                        invocation: self.id,
                        held,
                        max: MAX_UNDELIVERED_BYTES,
                    });
                } else {
                    *credits -= 1;
                    inbound.undelivered_bytes += payload.len();
                    inbound.chunks.entry(path).or_default().push_back(payload);
                }
            } else if inbound.undelivered_bytes + payload.len() > MAX_UNDELIVERED_BYTES {
                let held = inbound.undelivered_bytes + payload.len();
                inbound.fail_wire(WireError::InboundBacklogExceeded {
                    invocation: self.id,
                    held,
                    max: MAX_UNDELIVERED_BYTES,
                });
            } else {
                inbound.undelivered_bytes += payload.len();
                inbound.chunks.entry(path).or_default().push_back(payload);
            }
        }
        self.progress.signal();
    }

    async fn mark_closed(&self, path: Vec<usize>) {
        if path.is_empty() && matches!(self.owner, InvocationOwner::Server(_)) {
            self.cancelled.store(true, Ordering::Release);
        }
        {
            let mut inbound = self.inbound.lock().await;
            if inbound.error.is_some() {
                return;
            }
            if inbound.admits_path(&path) {
                inbound.closed.insert(path);
            } else {
                inbound.fail_wire(self.too_many_paths());
            }
        }
        self.progress.signal();
    }

    async fn grant_outbound_credit(&self, path: Vec<usize>, credits: u32) {
        if credits == 0 {
            let mut inbound = self.inbound.lock().await;
            let wire_path = path
                .iter()
                .map(|&segment| u32::try_from(segment).unwrap_or(u32::MAX))
                .collect();
            inbound.fail_wire(WireError::CreditOverflow {
                invocation: self.id,
                path: wire_path,
                credits,
            });
            drop(inbound);
            self.progress.signal();
            return;
        }
        let overflow = {
            let mut table = self.outbound_credits.lock().await;
            let entry = table.entry(path.clone()).or_insert(0);
            match entry.checked_add(credits) {
                Some(updated) => {
                    *entry = updated;
                    false
                }
                None => true,
            }
        };
        if overflow {
            let mut inbound = self.inbound.lock().await;
            let wire_path = path
                .iter()
                .map(|&segment| u32::try_from(segment).unwrap_or(u32::MAX))
                .collect();
            inbound.fail_wire(WireError::CreditOverflow {
                invocation: self.id,
                path: wire_path,
                credits,
            });
        }
        self.progress.signal();
    }

    fn too_many_paths(&self) -> WireError {
        WireError::TooManyInboundPaths {
            invocation: self.id,
            max: MAX_INBOUND_PATHS,
        }
    }

    async fn pop_payload(&self, path: &[usize]) -> Option<(Bytes, bool)> {
        let mut inbound = self.inbound.lock().await;
        let queue = inbound.chunks.get_mut(path)?;
        let chunk = queue.pop_front()?;
        if queue.is_empty() {
            inbound.chunks.remove(path);
        }
        inbound.undelivered_bytes -= chunk.len();
        let closed = inbound.closed.contains(path);
        let replenish = if let Some(credits) = inbound.credits.get_mut(path)
            && !closed
        {
            *credits = credits.saturating_add(1);
            true
        } else {
            false
        };
        Some((chunk, replenish))
    }

    fn mark_accepted(&self) {
        self.accepted.store(true, Ordering::Release);
    }

    async fn deliver_reply(&self, reply: Reply) {
        *self.reply.lock().await = Some(reply);
        self.progress.signal();
    }

    async fn take_reply(&self) -> Option<Reply> {
        self.reply.lock().await.take()
    }

    fn is_accepted(&self) -> bool {
        self.accepted.load(Ordering::Acquire)
    }

    async fn set_error(&self, message: String) {
        {
            let mut inbound = self.inbound.lock().await;
            if inbound.error.is_none() {
                inbound.error = Some(Fault::Remote(message));
            }
        }
        self.progress.signal();
    }

    async fn set_wire_error(&self, error: WireError) {
        {
            let mut inbound = self.inbound.lock().await;
            inbound.fail_wire(error);
        }
        self.progress.signal();
    }

    async fn ready_state(&self, path: &[usize]) -> Option<io::Result<()>> {
        let inbound = self.inbound.lock().await;
        if inbound
            .chunks
            .get(path)
            .is_some_and(|queue| !queue.is_empty())
            || inbound.closed.contains(path)
        {
            return Some(Ok(()));
        }
        inbound.error.as_ref().map(|fault| Err(fault.to_io()))
    }

    async fn failure(&self) -> Option<io::Error> {
        self.inbound.lock().await.error.as_ref().map(Fault::to_io)
    }
}

impl<R, W> Invocation<R, W>
where
    R: FuturesAsyncRead + Send + Unpin + 'static,
    W: FuturesAsyncWrite + Send + Unpin + 'static,
{
    async fn read_until_ready(self: Arc<Self>, path: Vec<usize>) -> io::Result<()> {
        loop {
            match &self.owner {
                InvocationOwner::Client(inner) => {
                    let inv_mark = self.progress.mark();
                    let Some(inner) = inner.upgrade() else {
                        return Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "client transport disappeared",
                        ));
                    };
                    let drv_mark = inner.driver_progress.mark();

                    if let Some(state) = self.ready_state(&path).await {
                        return state;
                    }
                    if inner.closed.load(Ordering::Acquire) {
                        return Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "client transport closed",
                        ));
                    }
                    futures_lite::future::or(
                        self.progress.changed(inv_mark),
                        inner.driver_progress.changed(drv_mark),
                    )
                    .await;
                }
                InvocationOwner::Server(inner) => {
                    if let Some(state) = self.ready_state(&path).await {
                        return state;
                    }
                    let inner = inner.upgrade().ok_or_else(|| {
                        io::Error::new(io::ErrorKind::BrokenPipe, "server transport disappeared")
                    })?;
                    if inner.closed.load(Ordering::Acquire) {
                        return Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "server transport closed",
                        ));
                    }
                    pump_server_once(inner).await.map_err(io::Error::other)?;
                }
            }
        }
    }

    async fn acquire_outbound_credit(&self, path: &[usize]) -> io::Result<()> {
        loop {
            let inv_mark = self.progress.mark();
            if let Some(error) = self.failure().await {
                return Err(error);
            }
            {
                let mut credits = self.outbound_credits.lock().await;
                if let Some(available) = credits.get_mut(path)
                    && *available > 0
                {
                    *available -= 1;
                    return Ok(());
                }
            }
            match &self.owner {
                InvocationOwner::Client(inner) => {
                    let Some(inner) = inner.upgrade() else {
                        return Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "client transport disappeared",
                        ));
                    };
                    let drv_mark = inner.driver_progress.mark();
                    if inner.closed.load(Ordering::Acquire) {
                        return Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "client transport closed",
                        ));
                    }
                    futures_lite::future::or(
                        self.progress.changed(inv_mark),
                        inner.driver_progress.changed(drv_mark),
                    )
                    .await;
                }
                InvocationOwner::Server(inner) => {
                    let inner = inner.upgrade().ok_or_else(|| {
                        io::Error::new(io::ErrorKind::BrokenPipe, "server transport disappeared")
                    })?;
                    if inner.closed.load(Ordering::Acquire) {
                        return Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "server transport closed",
                        ));
                    }
                    pump_server_once(inner).await.map_err(io::Error::other)?;
                }
            }
        }
    }

    async fn send_frame(&self, frame: Frame) -> io::Result<()> {
        match &self.owner {
            InvocationOwner::Client(inner) => {
                let inner = inner.upgrade().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::BrokenPipe, "client transport disappeared")
                })?;
                enqueue_client_frame(&inner, frame).await
            }
            InvocationOwner::Server(inner) => {
                write_owned_frame(&inner.upgrade(), &frame, "server transport disappeared").await
            }
        }
    }

    async fn write_data(
        self: Arc<Self>,
        path: Vec<usize>,
        payload: Bytes,
        credit_gated: bool,
    ) -> io::Result<()> {
        if credit_gated {
            self.acquire_outbound_credit(&path).await?;
        }
        let frame = Frame::Data {
            invocation: self.id,
            path: encode_path(&path)?,
            payload: payload.to_vec(),
        };
        self.send_frame(frame).await
    }

    async fn close_path(self: Arc<Self>, path: Vec<usize>) -> io::Result<()> {
        let frame = Frame::Close {
            invocation: self.id,
            path: encode_path(&path)?,
        };
        self.send_frame(frame).await
    }

    async fn send_credit(self: Arc<Self>, path: Vec<usize>, credits: u32) -> io::Result<()> {
        let frame = Frame::Credit {
            invocation: self.id,
            path: encode_path(&path)?,
            credits,
        };
        self.send_frame(frame).await
    }
}

impl<R, W> Incoming<R, W>
where
    R: FuturesAsyncRead + Send + Unpin + 'static,
    W: FuturesAsyncWrite + Send + Unpin + 'static,
{
    fn root(invocation: Arc<Invocation<R, W>>) -> Self {
        Self {
            invocation,
            path: Arc::from([]),
            credit_gated: false,
            current: None,
            pending: None,
            eof: false,
        }
    }

    /// Creates an [`Incoming`] reader on a nested sub-path of the same
    /// invocation.
    pub fn subpath(&self, segment: usize) -> Self {
        let mut next = self.path.to_vec();
        next.push(segment);
        Self {
            invocation: Arc::clone(&self.invocation),
            path: Arc::from(next),
            credit_gated: false,
            current: None,
            pending: None,
            eof: false,
        }
    }

    /// Enables explicit credit-based flow control on this sub-path and
    /// grants `window` initial credits to the remote sender.
    pub async fn with_credit_window(mut self, window: u32) -> io::Result<Self> {
        if window == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "stream credit window must be at least 1",
            ));
        }
        let path_vec = self.path.to_vec();
        {
            let mut inbound = self.invocation.inbound.lock().await;
            if !inbound.admits_path(&path_vec) {
                let err = self.invocation.too_many_paths();
                inbound.fail_wire(err.clone());
                return Err(err.into());
            }
            inbound.credits.insert(path_vec.clone(), window);
        }
        self.credit_gated = true;
        self.invocation
            .clone()
            .send_credit(path_vec, window)
            .await?;
        Ok(self)
    }

    pub fn is_invocation_cancelled(&self) -> bool {
        self.invocation.is_cancelled()
    }

    pub async fn invocation_cancelled(&self) {
        self.invocation.cancelled().await;
    }

    fn poll_read_into(&mut self, cx: &mut Context<'_>, out: &mut [u8]) -> Poll<io::Result<usize>> {
        if out.is_empty() || self.eof {
            return Poll::Ready(Ok(0));
        }

        loop {
            if let Some(current) = self.current.as_mut() {
                let count = current.len().min(out.len());
                out[..count].copy_from_slice(&current.split_to(count));
                if current.is_empty() {
                    self.current = None;
                }
                return Poll::Ready(Ok(count));
            }

            if self.pending.is_none() {
                let invocation = Arc::clone(&self.invocation);
                let path = self.path.to_vec();
                let credit_gated = self.credit_gated;
                self.pending = Some(Box::pin(async move {
                    loop {
                        if let Some((chunk, replenish)) = invocation.pop_payload(&path).await {
                            if credit_gated && replenish {
                                invocation.clone().send_credit(path.clone(), 1).await?;
                            }
                            if !chunk.is_empty() {
                                return Ok(Some(chunk));
                            }
                        }
                        {
                            let inbound = invocation.inbound.lock().await;
                            if inbound.closed.contains(path.as_slice())
                                && !inbound
                                    .chunks
                                    .get(path.as_slice())
                                    .is_some_and(|queue| !queue.is_empty())
                            {
                                return Ok(None);
                            }
                            if let Some(fault) = &inbound.error {
                                return Err(fault.to_io());
                            }
                        }
                        invocation.clone().read_until_ready(path.clone()).await?;
                    }
                }));
            }

            let future = self
                .pending
                .as_mut()
                .expect("incoming pending future must exist");
            match future.as_mut().poll(cx) {
                Poll::Ready(Ok(Some(chunk))) => {
                    self.pending = None;
                    self.current = Some(chunk);
                }
                Poll::Ready(Ok(None)) => {
                    self.pending = None;
                    self.eof = true;
                    return Poll::Ready(Ok(0));
                }
                Poll::Ready(Err(error)) => {
                    self.pending = None;
                    return Poll::Ready(Err(error));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<R, W> Outgoing<R, W> {
    fn root(invocation: Arc<Invocation<R, W>>) -> Self {
        Self {
            invocation,
            path: Arc::from([]),
            credit_gated: false,
            pending_write: None,
            pending_close: None,
            closed: false,
        }
    }

    /// Creates an [`Outgoing`] writer on a nested sub-path of the same
    /// invocation.
    pub fn subpath(&self, segment: usize) -> Self {
        let mut next = self.path.to_vec();
        next.push(segment);
        Self {
            invocation: Arc::clone(&self.invocation),
            path: Arc::from(next),
            credit_gated: false,
            pending_write: None,
            pending_close: None,
            closed: false,
        }
    }

    /// Requires explicit `Frame::Credit` grants from the remote peer before
    /// each `Data` frame written on this sub-path.
    pub fn with_credits(mut self) -> Self {
        self.credit_gated = true;
        self
    }
}

impl<R, W> Outgoing<R, W>
where
    R: FuturesAsyncRead + Send + Unpin + 'static,
    W: FuturesAsyncWrite + Send + Unpin + 'static,
{
    fn poll_write_slice(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        if self.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "attempted to write to a closed invocation stream",
            )));
        }

        if self.pending_write.is_none() {
            let chunk_len = buf.len().min(RAW_UPLOAD_CHUNK_BYTES);
            let bytes = Bytes::copy_from_slice(&buf[..chunk_len]);
            self.pending_write = Some((
                chunk_len,
                Box::pin(self.invocation.clone().write_data(
                    self.path.as_ref().to_vec(),
                    bytes,
                    self.credit_gated,
                )),
            ));
        }

        let (written, future) = self
            .pending_write
            .as_mut()
            .expect("outgoing pending write must exist");
        match future.as_mut().poll(cx) {
            Poll::Ready(Ok(())) => {
                let count = *written;
                self.pending_write = None;
                Poll::Ready(Ok(count))
            }
            Poll::Ready(Err(error)) => {
                self.pending_write = None;
                Poll::Ready(Err(error))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_close_stream(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.closed {
            return Poll::Ready(Ok(()));
        }

        if let Some((_, future)) = self.pending_write.as_mut() {
            match future.as_mut().poll(cx) {
                Poll::Ready(Ok(())) => {
                    self.pending_write = None;
                }
                Poll::Ready(Err(error)) => {
                    self.pending_write = None;
                    return Poll::Ready(Err(error));
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        if self.pending_close.is_none() {
            self.pending_close = Some(Box::pin(
                self.invocation
                    .clone()
                    .close_path(self.path.as_ref().to_vec()),
            ));
        }

        let future = self
            .pending_close
            .as_mut()
            .expect("outgoing pending close must exist");
        match future.as_mut().poll(cx) {
            Poll::Ready(Ok(())) => {
                self.pending_close = None;
                self.closed = true;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => {
                self.pending_close = None;
                Poll::Ready(Err(error))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<R, W> FuturesAsyncRead for Incoming<R, W>
where
    R: FuturesAsyncRead + Send + Unpin + 'static,
    W: FuturesAsyncWrite + Send + Unpin + 'static,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut().poll_read_into(cx, buf)
    }
}

#[cfg(feature = "host")]
impl<R, W> AsyncRead for Incoming<R, W>
where
    R: FuturesAsyncRead + Send + Unpin + 'static,
    W: FuturesAsyncWrite + Send + Unpin + 'static,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let unfilled = buf.initialize_unfilled();
        match self.get_mut().poll_read_into(cx, unfilled) {
            Poll::Ready(Ok(read)) => {
                buf.advance(read);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<R, W> FuturesAsyncWrite for Outgoing<R, W>
where
    R: FuturesAsyncRead + Send + Unpin + 'static,
    W: FuturesAsyncWrite + Send + Unpin + 'static,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut().poll_write_slice(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_close_stream(cx)
    }
}

#[cfg(feature = "host")]
impl<R, W> AsyncWrite for Outgoing<R, W>
where
    R: FuturesAsyncRead + Send + Unpin + 'static,
    W: FuturesAsyncWrite + Send + Unpin + 'static,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut().poll_write_slice(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_close_stream(cx)
    }
}

impl<R, W> Stream for InvocationStream<R, W>
where
    R: FuturesAsyncRead + Send + Unpin + 'static,
    W: FuturesAsyncWrite + Send + Unpin + 'static,
{
    type Item = Result<((), Outgoing<R, W>, Incoming<R, W>)>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            match this.rx.as_mut().poll_next(cx) {
                Poll::Ready(Some(item)) => return Poll::Ready(Some(item)),
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => {}
            }

            if this.server.closed.load(Ordering::Acquire) {
                return Poll::Ready(None);
            }

            if this.pending.is_none() {
                this.pending = Some(Box::pin(pump_server_once(this.server.clone())));
            }

            let future = this
                .pending
                .as_mut()
                .expect("server pump future must exist");
            match future.as_mut().poll(cx) {
                Poll::Ready(Ok(())) => {
                    this.pending = None;
                }
                Poll::Ready(Err(error)) => {
                    this.pending = None;
                    return Poll::Ready(Some(Err(error)));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

async fn register_invocation<R, W>(
    active: &Mutex<HashMap<u32, Weak<Invocation<R, W>>>>,
    invocation: &Arc<Invocation<R, W>>,
) {
    let mut table = active.lock().await;
    table.retain(|_, weak| weak.strong_count() > 0);
    table.insert(invocation.id, Arc::downgrade(invocation));
}

async fn resolve_invocation<R, W>(
    active: &Mutex<HashMap<u32, Weak<Invocation<R, W>>>>,
    invocation: u32,
) -> Option<Arc<Invocation<R, W>>> {
    let mut table = active.lock().await;
    match table.get(&invocation).and_then(Weak::upgrade) {
        Some(target) => Some(target),
        None => {
            table.remove(&invocation);
            None
        }
    }
}

async fn enqueue_client_frame<R, W>(client: &ClientInner<R, W>, frame: Frame) -> io::Result<()> {
    if client.closed.load(Ordering::Acquire) {
        return Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "client transport closed",
        ));
    }
    let (completion, finished) = async_channel::bounded(1);
    client
        .outgoing
        .send(PendingFrame { frame, completion })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "client writer stopped"))?;
    finished
        .recv()
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "client writer stopped"))?
}

async fn route_client_frame<R, W>(client: &Arc<ClientInner<R, W>>, frame: Frame) -> io::Result<()> {
    match frame {
        Frame::Accept { invocation } => {
            if let Some(target) = resolve_invocation(&client.active, invocation).await {
                target.mark_accepted();
                target.deliver_reply(Reply::Accept).await;
            }
        }
        Frame::Reject {
            invocation,
            message,
        } => {
            if let Some(target) = resolve_invocation(&client.active, invocation).await {
                if target.is_accepted() {
                    target.set_error(message).await;
                } else {
                    target.deliver_reply(Reply::Reject(message)).await;
                }
            }
        }
        Frame::Fault { invocation, error } => {
            if let Some(target) = resolve_invocation(&client.active, invocation).await {
                if target.is_accepted() {
                    target.set_wire_error(error).await;
                } else {
                    target.deliver_reply(Reply::Fault(error)).await;
                }
            }
        }
        Frame::Data {
            invocation,
            path,
            payload,
        } => {
            if let Some(target) = resolve_invocation(&client.active, invocation).await {
                target
                    .push_payload(decode_path(&path)?, Bytes::from(payload))
                    .await;
            }
        }
        Frame::Close { invocation, path } => {
            if let Some(target) = resolve_invocation(&client.active, invocation).await {
                target.mark_closed(decode_path(&path)?).await;
            }
        }
        Frame::Credit {
            invocation,
            path,
            credits,
        } => {
            if let Some(target) = resolve_invocation(&client.active, invocation).await {
                target
                    .grant_outbound_credit(decode_path(&path)?, credits)
                    .await;
            }
        }
        Frame::Open { .. } | Frame::ResourceDrop { .. } => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "client transport received unexpected server-only frame",
            ));
        }
    }

    Ok(())
}

async fn close_client<R, W>(client: &Arc<ClientInner<R, W>>, reason: &str) {
    client.closed.store(true, Ordering::Release);
    let waiting: Vec<Arc<Invocation<R, W>>> = client
        .active
        .lock()
        .await
        .values()
        .filter_map(Weak::upgrade)
        .collect();
    for invocation in waiting {
        invocation.set_error(reason.to_owned()).await;
    }
    client.driver_progress.signal();
}

async fn pump_server_once<R, W>(server: Arc<ServerInner<R, W>>) -> Result<()>
where
    R: FuturesAsyncRead + Send + Unpin + 'static,
    W: FuturesAsyncWrite + Send + Unpin + 'static,
{
    if server.closed.load(Ordering::Acquire) {
        return Ok(());
    }

    let handoff = {
        let mut registrations = server.dispatch.lock().await;
        while let Ok((key, reg)) = server.register_rx.try_recv() {
            let previous = registrations.insert(key.clone(), reg);
            assert!(
                previous.is_none(),
                "duplicate handler registration for {}.{}",
                key.0,
                key.1
            );
        }

        let frame = {
            let mut io = server.read.lock().await;
            match read_frame(&mut *io)
                .await
                .map_err(|source| TransportError::io("read server transport frame", source))?
            {
                Some(frame) => frame,
                None => {
                    mark_server_closed(&server, &mut registrations).await;
                    return Ok(());
                }
            }
        };

        match frame {
            Frame::Open {
                invocation,
                instance,
                func,
            } => {
                let registration = registrations
                    .get(&(instance.clone(), func.clone()))
                    .cloned();

                match registration {
                    Some(registration) => {
                        {
                            let mut io = server.write.lock().await;
                            write_frame(&mut *io, &Frame::Accept { invocation })
                                .await
                                .map_err(|source| {
                                    TransportError::io("accept remote invocation", source)
                                })?;
                        }

                        let invocation = Invocation::new_server(invocation, &server).await;
                        Some((
                            registration,
                            Ok((
                                (),
                                Outgoing::root(invocation.clone()),
                                Incoming::root(invocation),
                            )),
                            instance,
                            func,
                        ))
                    }
                    None => {
                        let mut io = server.write.lock().await;
                        write_frame(
                            &mut *io,
                            &Frame::Reject {
                                invocation,
                                message: format!("no handler registered for {instance}.{func}"),
                            },
                        )
                        .await
                        .map_err(|source| TransportError::io("reject remote invocation", source))?;
                        None
                    }
                }
            }
            Frame::Data {
                invocation,
                path,
                payload,
            } => {
                if let Some(target) = resolve_invocation(&server.active, invocation).await {
                    let decoded = decode_path(&path).map_err(|source| {
                        TransportError::io("decode incoming data path", source)
                    })?;
                    target.push_payload(decoded, Bytes::from(payload)).await;
                }
                None
            }
            Frame::Close { invocation, path } => {
                if let Some(target) = resolve_invocation(&server.active, invocation).await {
                    let decoded = decode_path(&path).map_err(|source| {
                        TransportError::io("decode incoming close path", source)
                    })?;
                    target.mark_closed(decoded).await;
                }
                None
            }
            Frame::Credit {
                invocation,
                path,
                credits,
            } => {
                if let Some(target) = resolve_invocation(&server.active, invocation).await {
                    let decoded = decode_path(&path).map_err(|source| {
                        TransportError::io("decode incoming credit path", source)
                    })?;
                    target.grant_outbound_credit(decoded, credits).await;
                }
                None
            }
            Frame::ResourceDrop { .. } => None,
            Frame::Accept { .. } | Frame::Reject { .. } | Frame::Fault { .. } => {
                return Err(TransportError::UnexpectedReply);
            }
        }
    };

    if let Some((registration, invocation, instance, func)) = handoff {
        registration
            .tx
            .send(invocation)
            .await
            .map_err(|_| TransportError::HandoffClosed { instance, func })?;
    }

    Ok(())
}

async fn mark_server_closed<R, W>(
    server: &ServerInner<R, W>,
    registrations: &mut HashMap<(String, String), Registration<R, W>>,
) {
    server.closed.store(true, Ordering::Release);
    server.register_rx.close();
    registrations.clear();
    server.active.lock().await.clear();
}

async fn write_owned_frame<W, I>(
    owner: &Option<Arc<I>>,
    frame: &Frame,
    disappeared: &'static str,
) -> io::Result<()>
where
    W: FuturesAsyncWrite + Send + Unpin + 'static,
    I: FrameWriter<W>,
{
    let owner = owner
        .as_ref()
        .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, disappeared))?;
    let mut io = owner.write().lock().await;
    write_frame(&mut *io, frame).await
}

trait FrameWriter<W> {
    fn write(&self) -> &Arc<Mutex<W>>;
}

impl<R, W> FrameWriter<W> for ServerInner<R, W> {
    fn write(&self) -> &Arc<Mutex<W>> {
        &self.write
    }
}

fn encode_path(path: &[usize]) -> io::Result<Vec<u32>> {
    path.iter()
        .map(|index| {
            u32::try_from(*index)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
        })
        .collect()
}

fn decode_path(path: &[u32]) -> io::Result<Vec<usize>> {
    path.iter()
        .map(|index| {
            usize::try_from(*index)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
        })
        .collect()
}

#[cfg(all(test, feature = "host"))]
mod tests {
    use super::{Client, MAX_INBOUND_PATHS, MAX_UNDELIVERED_BYTES, RAW_UPLOAD_CHUNK_BYTES, Server};
    use crate::error::WireError;
    use bytes::Bytes;
    use futures_lite::StreamExt as _;
    use futures_lite::future::poll_once;
    use futures_util::future::join;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream, ReadHalf, WriteHalf};
    use tokio::sync::Notify;
    use tokio::time::{Duration, timeout};
    use tokio_util::compat::{Compat, TokioAsyncReadCompatExt as _, TokioAsyncWriteCompatExt as _};

    const CONCURRENT_DEADLINE: Duration = Duration::from_secs(5);

    #[test]
    fn sequential_empty_invocations_do_not_stall() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap_or_else(|error| panic!("failed to build test runtime: {error}"))
            .block_on(async {
                let (host, peer) = tokio::io::duplex(4096);
                let (host_read, host_write) = tokio::io::split(host);
                let server = Server::new(host_read.compat(), host_write.compat_write());
                let (peer_read, peer_write) = tokio::io::split(peer);
                let client = Client::new(peer_read.compat(), peer_write.compat_write());
                let driver = client.clone();
                tokio::spawn(async move { driver.route_frames().await });

                let mut invocations = server
                    .serve("transport:test", "ping")
                    .unwrap_or_else(|error| panic!("failed to register server handler: {error}"));
                let server_task = tokio::spawn(async move {
                    for response in ["one", "two"] {
                        let (_, mut outgoing, mut incoming) = invocations
                            .next()
                            .await
                            .unwrap_or_else(|| panic!("server invocation stream ended early"))
                            .unwrap_or_else(|error| {
                                panic!("failed to accept server invocation: {error}")
                            });
                        let mut request = Vec::new();
                        incoming
                            .read_to_end(&mut request)
                            .await
                            .unwrap_or_else(|error| {
                                panic!("failed to read request payload: {error}")
                            });
                        assert!(
                            request.is_empty(),
                            "unexpected request payload: {request:?}"
                        );
                        outgoing
                            .write_all(response.as_bytes())
                            .await
                            .unwrap_or_else(|error| {
                                panic!("failed to write response payload: {error}")
                            });
                        outgoing.shutdown().await.unwrap_or_else(|error| {
                            panic!("failed to close response stream: {error}")
                        });
                    }
                });

                assert_eq!(
                    client
                        .invoke_raw("transport:test", "ping", Vec::new())
                        .await
                        .unwrap_or_else(|error| panic!("first raw invocation failed: {error}")),
                    b"one"
                );
                assert_eq!(
                    client
                        .invoke_raw("transport:test", "ping", Vec::new())
                        .await
                        .unwrap_or_else(|error| panic!("second raw invocation failed: {error}")),
                    b"two"
                );

                server_task
                    .await
                    .unwrap_or_else(|error| panic!("server task panicked: {error}"));
            });
    }

    #[test]
    fn active_invocation_does_not_block_next_call() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap_or_else(|error| panic!("failed to build test runtime: {error}"))
            .block_on(async {
                let (host, peer) = tokio::io::duplex(4096);
                let (host_read, host_write) = tokio::io::split(host);
                let server = Server::new(host_read.compat(), host_write.compat_write());
                let (peer_read, peer_write) = tokio::io::split(peer);
                let client = Client::new(peer_read.compat(), peer_write.compat_write());
                let driver = client.clone();
                tokio::spawn(async move { driver.route_frames().await });
                let released = std::sync::Arc::new(Notify::new());

                let mut stream_calls = server
                    .serve("transport:test", "stream")
                    .unwrap_or_else(|error| panic!("failed to register stream handler: {error}"));
                let stream_release = released.clone();
                let stream_task = tokio::spawn(async move {
                    let (_, mut outgoing, mut incoming) = stream_calls
                        .next()
                        .await
                        .unwrap_or_else(|| panic!("stream invocation stream ended early"))
                        .unwrap_or_else(|error| {
                            panic!("failed to accept stream invocation: {error}")
                        });
                    let mut request = Vec::new();
                    incoming
                        .read_to_end(&mut request)
                        .await
                        .unwrap_or_else(|error| panic!("failed to read stream request: {error}"));
                    assert!(
                        request.is_empty(),
                        "unexpected stream request payload: {request:?}"
                    );
                    outgoing
                        .write_all(b"stream")
                        .await
                        .unwrap_or_else(|error| panic!("failed to write stream response: {error}"));
                    stream_release.notified().await;
                    outgoing
                        .shutdown()
                        .await
                        .unwrap_or_else(|error| panic!("failed to close stream response: {error}"));
                });

                let mut ping_calls = server
                    .serve("transport:test", "ping")
                    .unwrap_or_else(|error| panic!("failed to register ping handler: {error}"));
                let ping_release = released.clone();
                let ping_task =
                    tokio::spawn(async move {
                        let (_, mut outgoing, mut incoming) = ping_calls
                            .next()
                            .await
                            .unwrap_or_else(|| panic!("ping invocation stream ended early"))
                            .unwrap_or_else(|error| {
                                panic!("failed to accept ping invocation: {error}")
                            });
                        let mut request = Vec::new();
                        incoming
                            .read_to_end(&mut request)
                            .await
                            .unwrap_or_else(|error| panic!("failed to read ping request: {error}"));
                        assert!(
                            request.is_empty(),
                            "unexpected ping request payload: {request:?}"
                        );
                        outgoing.write_all(b"pong").await.unwrap_or_else(|error| {
                            panic!("failed to write ping response: {error}")
                        });
                        outgoing.shutdown().await.unwrap_or_else(|error| {
                            panic!("failed to close ping response: {error}")
                        });
                        ping_release.notify_one();
                    });

                let (mut first_outgoing, mut first_incoming) = client
                    .open_invocation("transport:test", "stream", Bytes::new())
                    .await
                    .unwrap_or_else(|error| panic!("failed to open stream invocation: {error}"));
                first_outgoing.shutdown().await.unwrap_or_else(|error| {
                    panic!("failed to close stream request channel: {error}")
                });

                assert_eq!(
                    client
                        .invoke_raw("transport:test", "ping", Vec::new())
                        .await
                        .unwrap_or_else(|error| panic!("ping invocation failed: {error}")),
                    b"pong"
                );

                let mut response = Vec::new();
                first_incoming
                    .read_to_end(&mut response)
                    .await
                    .unwrap_or_else(|error| panic!("failed to read stream response: {error}"));
                assert_eq!(response, b"stream");

                stream_task
                    .await
                    .unwrap_or_else(|error| panic!("stream task panicked: {error}"));
                ping_task
                    .await
                    .unwrap_or_else(|error| panic!("ping task panicked: {error}"));
            });
    }

    #[test]
    fn accepted_invocation_can_fail_without_tearing_down_transport() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap_or_else(|error| panic!("failed to build test runtime: {error}"))
            .block_on(async {
                let (host, peer) = tokio::io::duplex(4096);
                let (host_read, host_write) = tokio::io::split(host);
                let server = Server::new(host_read.compat(), host_write.compat_write());
                let (peer_read, peer_write) = tokio::io::split(peer);
                let client = Client::new(peer_read.compat(), peer_write.compat_write());
                let driver = client.clone();
                tokio::spawn(async move { driver.route_frames().await });

                let mut calls = server
                    .serve("transport:test", "fail")
                    .unwrap_or_else(|error| panic!("failed to register fail handler: {error}"));
                let server_task = tokio::spawn(async move {
                    let (_, _outgoing, mut incoming) = calls
                        .next()
                        .await
                        .unwrap_or_else(|| panic!("fail invocation stream ended early"))
                        .unwrap_or_else(|error| {
                            panic!("failed to accept fail invocation: {error}")
                        });
                    let mut request = Vec::new();
                    incoming
                        .read_to_end(&mut request)
                        .await
                        .unwrap_or_else(|error| panic!("failed to read fail request: {error}"));
                    assert_eq!(request, b"request");

                    let mut io = server.inner.write.lock().await;
                    super::write_frame(
                        &mut *io,
                        &super::Frame::Reject {
                            invocation: 1,
                            message: "remote failure".to_owned(),
                        },
                    )
                    .await
                    .unwrap_or_else(|error| panic!("failed to write reject frame: {error}"));
                });

                let error = client
                    .invoke_raw("transport:test", "fail", b"request".to_vec())
                    .await
                    .expect_err("accepted invocation must surface remote failure");
                assert!(
                    format!("{error:#}").contains("remote failure"),
                    "unexpected error: {error:#}"
                );

                server_task
                    .await
                    .unwrap_or_else(|error| panic!("fail server task panicked: {error}"));
            });
    }

    fn round_trip(func: &'static str, responses: &[&'static [u8]]) -> Vec<Vec<u8>> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap_or_else(|error| panic!("failed to build test runtime: {error}"))
            .block_on(async move {
                let (host, peer) = tokio::io::duplex(4096);
                let (host_read, host_write) = tokio::io::split(host);
                let server = Server::new(host_read.compat(), host_write.compat_write());
                let (peer_read, peer_write) = tokio::io::split(peer);
                let client = Client::new(peer_read.compat(), peer_write.compat_write());
                let driver = client.clone();
                tokio::spawn(async move { driver.route_frames().await });

                let mut invocations =
                    server
                        .serve("transport:test", func)
                        .unwrap_or_else(|error| {
                            panic!("failed to register the {func} handler: {error}")
                        });
                let answers = responses.to_vec();
                let server_task = tokio::spawn(async move {
                    for response in answers {
                        let (_, mut outgoing, mut incoming) = invocations
                            .next()
                            .await
                            .unwrap_or_else(|| panic!("the {func} stream ended early"))
                            .unwrap_or_else(|error| {
                                panic!("failed to accept a {func} invocation: {error}")
                            });
                        let mut request = Vec::new();
                        incoming
                            .read_to_end(&mut request)
                            .await
                            .unwrap_or_else(|error| {
                                panic!("failed to read the {func} request: {error}")
                            });
                        assert!(
                            request.is_empty(),
                            "unexpected {func} request payload: {request:?}"
                        );
                        outgoing.write_all(response).await.unwrap_or_else(|error| {
                            panic!("failed to write the {func} response: {error}")
                        });
                        outgoing.shutdown().await.unwrap_or_else(|error| {
                            panic!("failed to close the {func} response stream: {error}")
                        });
                    }
                });

                let mut read = Vec::new();
                for _ in responses {
                    read.push(
                        client
                            .invoke_raw("transport:test", func, Vec::new())
                            .await
                            .unwrap_or_else(|error| {
                                panic!("the {func} invocation failed: {error}")
                            }),
                    );
                }
                server_task
                    .await
                    .unwrap_or_else(|error| panic!("the {func} server task panicked: {error}"));
                read
            })
    }

    #[test]
    fn sequential_invocations_keep_their_own_short_answers() {
        assert_eq!(
            round_trip("unit", &[&[7], &[11]]),
            vec![vec![7_u8], vec![11_u8]]
        );
    }

    #[test]
    fn a_single_byte_response_is_not_read_as_an_empty_one() {
        assert_eq!(round_trip("resource", &[&[0]]), vec![vec![0_u8]]);
    }

    #[test]
    fn a_multi_byte_response_arrives_whole() {
        assert_eq!(
            round_trip("resource-some", &[&[1, 4, 0x12, 0x34, 0x56, 0x78]]),
            vec![vec![1, 4, 0x12, 0x34, 0x56, 0x78]]
        );
    }

    #[test]
    fn an_all_zero_response_payload_arrives_whole() {
        assert_eq!(
            round_trip("resource-zero", &[&[1, 4, 0, 0, 0, 0]]),
            vec![vec![1, 4, 0, 0, 0, 0]]
        );
    }

    #[test]
    fn large_raw_response_is_chunked_across_frames() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap_or_else(|error| panic!("failed to build test runtime: {error}"))
            .block_on(async {
                let (host, peer) = tokio::io::duplex(4096);
                let (host_read, host_write) = tokio::io::split(host);
                let server = Server::new(host_read.compat(), host_write.compat_write());
                let (peer_read, peer_write) = tokio::io::split(peer);
                let client = Client::new(peer_read.compat(), peer_write.compat_write());
                let driver = client.clone();
                tokio::spawn(async move { driver.route_frames().await });

                let expected = vec![0x5a; RAW_UPLOAD_CHUNK_BYTES * 3 + 17];
                let mut calls = server
                    .serve("transport:test", "large-response")
                    .unwrap_or_else(|error| {
                        panic!("failed to register large-response handler: {error}")
                    });
                let expected_response = expected.clone();
                let server_task = tokio::spawn(async move {
                    let (_, mut outgoing, mut incoming) = calls
                        .next()
                        .await
                        .unwrap_or_else(|| panic!("large-response invocation stream ended early"))
                        .unwrap_or_else(|error| {
                            panic!("failed to accept large-response invocation: {error}")
                        });
                    let mut request = Vec::new();
                    incoming
                        .read_to_end(&mut request)
                        .await
                        .unwrap_or_else(|error| {
                            panic!("failed to read large-response request: {error}")
                        });
                    assert!(
                        request.is_empty(),
                        "unexpected request payload: {request:?}"
                    );
                    outgoing
                        .write_all(&expected_response)
                        .await
                        .unwrap_or_else(|error| {
                            panic!("failed to write large-response payload: {error}")
                        });
                    outgoing.shutdown().await.unwrap_or_else(|error| {
                        panic!("failed to close large-response stream: {error}")
                    });
                });

                let actual = client
                    .invoke_raw("transport:test", "large-response", Vec::new())
                    .await
                    .unwrap_or_else(|error| panic!("large-response invocation failed: {error}"));
                assert_eq!(actual, expected);

                server_task
                    .await
                    .unwrap_or_else(|error| panic!("large-response server task panicked: {error}"));
            });
    }

    #[test]
    fn queued_open_does_not_block_active_invocation_progress() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap_or_else(|error| panic!("failed to build test runtime: {error}"))
            .block_on(async {
                let (host, peer) = tokio::io::duplex(4096);
                let (host_read, host_write) = tokio::io::split(host);
                let server = Server::new(host_read.compat(), host_write.compat_write());
                let (peer_read, peer_write) = tokio::io::split(peer);
                let mut peer_read = peer_read.compat();
                let mut peer_write = peer_write.compat_write();

                let mut invocations = server
                    .serve("transport:test", "queue")
                    .unwrap_or_else(|error| panic!("failed to register queue handler: {error}"));

                super::write_frame(
                    &mut peer_write,
                    &super::Frame::Open {
                        invocation: 1,
                        instance: "transport:test".to_owned(),
                        func: "queue".to_owned(),
                    },
                )
                .await
                .unwrap_or_else(|error| panic!("failed to write first open frame: {error}"));
                super::pump_server_once(server.inner.clone())
                    .await
                    .unwrap_or_else(|error| panic!("failed to accept first invocation: {error}"));
                match super::read_frame(&mut peer_read)
                    .await
                    .unwrap_or_else(|error| panic!("failed to read first accept frame: {error}"))
                {
                    Some(super::Frame::Accept { invocation }) => assert_eq!(invocation, 1),
                    other => panic!("unexpected first accept frame: {other:?}"),
                }

                let (_, _first_outgoing, mut first_incoming) = invocations
                    .next()
                    .await
                    .unwrap_or_else(|| panic!("first invocation stream ended early"))
                    .unwrap_or_else(|error| panic!("failed to receive first invocation: {error}"));

                for invocation in 2..=9 {
                    super::write_frame(
                        &mut peer_write,
                        &super::Frame::Open {
                            invocation,
                            instance: "transport:test".to_owned(),
                            func: "queue".to_owned(),
                        },
                    )
                    .await
                    .unwrap_or_else(|error| {
                        panic!("failed to write queued open frame {invocation}: {error}")
                    });
                    super::pump_server_once(server.inner.clone())
                        .await
                        .unwrap_or_else(|error| {
                            panic!("failed to pump queued open frame {invocation}: {error}")
                        });
                    match super::read_frame(&mut peer_read)
                        .await
                        .unwrap_or_else(|error| {
                            panic!("failed to read queued accept frame {invocation}: {error}")
                        }) {
                        Some(super::Frame::Accept {
                            invocation: accepted,
                        }) => {
                            assert_eq!(accepted, invocation);
                        }
                        other => panic!(
                            "unexpected queued accept frame for invocation {invocation}: {other:?}"
                        ),
                    }
                }

                super::write_frame(
                    &mut peer_write,
                    &super::Frame::Open {
                        invocation: 10,
                        instance: "transport:test".to_owned(),
                        func: "queue".to_owned(),
                    },
                )
                .await
                .unwrap_or_else(|error| panic!("failed to write blocked open frame: {error}"));

                let blocked_pump = tokio::spawn({
                    let server = server.inner.clone();
                    async move { super::pump_server_once(server).await }
                });

                match super::read_frame(&mut peer_read)
                    .await
                    .unwrap_or_else(|error| panic!("failed to read blocked accept frame: {error}"))
                {
                    Some(super::Frame::Accept { invocation }) => assert_eq!(invocation, 10),
                    other => panic!("unexpected blocked accept frame: {other:?}"),
                }

                tokio::task::yield_now().await;

                super::write_frame(
                    &mut peer_write,
                    &super::Frame::Data {
                        invocation: 1,
                        path: Vec::new(),
                        payload: b"request".to_vec(),
                    },
                )
                .await
                .unwrap_or_else(|error| panic!("failed to write active request data: {error}"));
                super::write_frame(
                    &mut peer_write,
                    &super::Frame::Close {
                        invocation: 1,
                        path: Vec::new(),
                    },
                )
                .await
                .unwrap_or_else(|error| panic!("failed to write active request close: {error}"));

                let mut request = Vec::new();
                timeout(
                    Duration::from_millis(100),
                    first_incoming.read_to_end(&mut request),
                )
                .await
                .unwrap_or_else(|_| panic!("active invocation stalled behind queued open"))
                .unwrap_or_else(|error| {
                    panic!("failed to read active invocation payload: {error}")
                });
                assert_eq!(request, b"request");

                let _ = invocations
                    .next()
                    .await
                    .unwrap_or_else(|| panic!("queued invocation stream ended unexpectedly"))
                    .unwrap_or_else(|error| panic!("failed to release queued invocation: {error}"));

                blocked_pump
                    .await
                    .unwrap_or_else(|error| panic!("blocked pump task panicked: {error}"))
                    .unwrap_or_else(|error| panic!("blocked pump failed: {error}"));
            });
    }

    #[test]
    fn concurrently_held_invocations_both_complete() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap_or_else(|error| panic!("failed to build test runtime: {error}"))
            .block_on(async {
                let (host, peer) = tokio::io::duplex(4096);
                let (host_read, host_write) = tokio::io::split(host);
                let server = Server::new(host_read.compat(), host_write.compat_write());
                let (peer_read, peer_write) = tokio::io::split(peer);
                let client = Client::new(peer_read.compat(), peer_write.compat_write());
                let driver = client.clone();
                tokio::spawn(async move { driver.route_frames().await });
                let release = std::sync::Arc::new(Notify::new());

                let mut slow_calls = server
                    .serve("transport:test", "slow")
                    .unwrap_or_else(|error| panic!("failed to register slow handler: {error}"));
                let slow_release = release.clone();
                let slow_task =
                    tokio::spawn(async move {
                        let (_, mut outgoing, mut incoming) = slow_calls
                            .next()
                            .await
                            .unwrap_or_else(|| panic!("slow invocation stream ended early"))
                            .unwrap_or_else(|error| {
                                panic!("failed to accept slow invocation: {error}")
                            });
                        let mut request = Vec::new();
                        incoming
                            .read_to_end(&mut request)
                            .await
                            .unwrap_or_else(|error| panic!("failed to read slow request: {error}"));
                        slow_release.notified().await;
                        outgoing.write_all(b"slow").await.unwrap_or_else(|error| {
                            panic!("failed to write slow response: {error}")
                        });
                        outgoing.shutdown().await.unwrap_or_else(|error| {
                            panic!("failed to close slow response: {error}")
                        });
                    });

                let mut probe_calls = server
                    .serve("transport:test", "probe")
                    .unwrap_or_else(|error| panic!("failed to register probe handler: {error}"));
                let probe_task = tokio::spawn(async move {
                    let (_, mut outgoing, mut incoming) = probe_calls
                        .next()
                        .await
                        .unwrap_or_else(|| panic!("probe invocation stream ended early"))
                        .unwrap_or_else(|error| {
                            panic!("failed to accept probe invocation: {error}")
                        });
                    let mut request = Vec::new();
                    incoming
                        .read_to_end(&mut request)
                        .await
                        .unwrap_or_else(|error| panic!("failed to read probe request: {error}"));
                    outgoing
                        .write_all(b"pong")
                        .await
                        .unwrap_or_else(|error| panic!("failed to write probe response: {error}"));
                    outgoing
                        .shutdown()
                        .await
                        .unwrap_or_else(|error| panic!("failed to close probe response: {error}"));
                });

                let (mut slow_outgoing, mut slow_incoming) = client
                    .open_invocation("transport:test", "slow", Bytes::new())
                    .await
                    .unwrap_or_else(|error| panic!("failed to open slow invocation: {error}"));
                slow_outgoing.shutdown().await.unwrap_or_else(|error| {
                    panic!("failed to close slow request channel: {error}")
                });

                let held = async {
                    let mut response = Vec::new();
                    slow_incoming
                        .read_to_end(&mut response)
                        .await
                        .unwrap_or_else(|error| panic!("failed to read slow response: {error}"));
                    assert_eq!(response, b"slow");
                };
                let concurrent = async {
                    let answer = timeout(
                        CONCURRENT_DEADLINE,
                        client.invoke_raw("transport:test", "probe", Vec::new()),
                    )
                    .await
                    .unwrap_or_else(|_| {
                        panic!(
                            "the second invocation went unanswered for {CONCURRENT_DEADLINE:?} \
                             while the first was held open"
                        )
                    })
                    .unwrap_or_else(|error| panic!("probe invocation failed: {error}"));
                    assert_eq!(answer, b"pong");
                    release.notify_one();
                };
                join(held, concurrent).await;

                slow_task
                    .await
                    .unwrap_or_else(|error| panic!("slow server task panicked: {error}"));
                probe_task
                    .await
                    .unwrap_or_else(|error| panic!("probe server task panicked: {error}"));
            });
    }

    #[test]
    fn an_answer_filed_while_its_caller_parks_is_delivered() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap_or_else(|error| panic!("failed to build test runtime: {error}"))
            .block_on(async {
                let (guest, peer) = tokio::io::duplex(4096);
                let (guest_read, guest_write) = tokio::io::split(guest);
                let mut guest_read = guest_read.compat();
                let mut guest_write = guest_write.compat_write();
                let (peer_read, peer_write) = tokio::io::split(peer);
                let client = Client::new(peer_read.compat(), peer_write.compat_write());
                let driver = client.clone();
                tokio::spawn(async move { driver.route_frames().await });

                let mut reader =
                    Box::pin(client.open_invocation("transport:test", "reader", Bytes::new()));
                assert!(
                    poll_once(&mut reader).await.is_none(),
                    "the first caller must park until the guest answers it"
                );
                assert!(matches!(
                    super::read_frame(&mut guest_read).await.unwrap(),
                    Some(super::Frame::Open { invocation: 1, .. })
                ));
                let mut waiter =
                    Box::pin(client.open_invocation("transport:test", "waiter", Bytes::new()));
                assert!(
                    poll_once(&mut waiter).await.is_none(),
                    "the second caller must park until the guest answers it"
                );

                for expected in ["waiter"] {
                    match super::read_frame(&mut guest_read)
                        .await
                        .unwrap_or_else(|error| {
                            panic!("failed to read the {expected} open frame: {error}")
                        }) {
                        Some(super::Frame::Open { func, .. }) => assert_eq!(func, expected),
                        other => panic!("unexpected {expected} open frame: {other:?}"),
                    }
                }

                for frame in [
                    super::Frame::Accept { invocation: 2 },
                    super::Frame::Data {
                        invocation: 2,
                        path: Vec::new(),
                        payload: b"answered".to_vec(),
                    },
                    super::Frame::Close {
                        invocation: 2,
                        path: Vec::new(),
                    },
                    super::Frame::Accept { invocation: 1 },
                ] {
                    super::write_frame(&mut guest_write, &frame)
                        .await
                        .unwrap_or_else(|error| panic!("failed to write {frame:?}: {error}"));
                }

                let (reading, parked) = timeout(CONCURRENT_DEADLINE, join(reader, waiter))
                    .await
                    .unwrap_or_else(|_| panic!("a caller never saw the accept filed for it"));
                let (_reader_outgoing, _reader_incoming) = reading
                    .unwrap_or_else(|error| panic!("the reading invocation failed: {error}"));
                let (_waiter_outgoing, mut waiter_incoming) =
                    parked.unwrap_or_else(|error| panic!("the parked invocation failed: {error}"));

                let mut response = Vec::new();
                timeout(
                    CONCURRENT_DEADLINE,
                    waiter_incoming.read_to_end(&mut response),
                )
                .await
                .unwrap_or_else(|_| panic!("the parked caller never saw the payload filed for it"))
                .unwrap_or_else(|error| panic!("failed to read the parked response: {error}"));
                assert_eq!(response, b"answered");
            });
    }

    type TestRead = Compat<ReadHalf<DuplexStream>>;
    type TestWrite = Compat<WriteHalf<DuplexStream>>;

    struct RawPeer {
        client: Client<TestRead, TestWrite>,
        read: TestRead,
        write: TestWrite,
    }

    impl RawPeer {
        fn new() -> Self {
            let (guest, host) = tokio::io::duplex(4096);
            let (guest_read, guest_write) = tokio::io::split(guest);
            let (host_read, host_write) = tokio::io::split(host);
            let client = Client::new(host_read.compat(), host_write.compat_write());
            let driver = client.clone();
            tokio::spawn(async move { driver.route_frames().await });
            Self {
                client,
                read: guest_read.compat(),
                write: guest_write.compat_write(),
            }
        }

        async fn open(
            &mut self,
            func: &str,
            id: u32,
        ) -> (
            super::Outgoing<TestRead, TestWrite>,
            super::Incoming<TestRead, TestWrite>,
        ) {
            let guest = async {
                match super::read_frame(&mut self.read)
                    .await
                    .unwrap_or_else(|error| panic!("failed to read the {func} open: {error}"))
                {
                    Some(super::Frame::Open { invocation, .. }) => assert_eq!(invocation, id),
                    other => panic!("unexpected {func} open frame: {other:?}"),
                }
                super::write_frame(&mut self.write, &super::Frame::Accept { invocation: id })
                    .await
                    .unwrap_or_else(|error| panic!("failed to accept {func}: {error}"));
            };
            let (opened, ()) = join(
                self.client
                    .open_invocation("transport:test", func, Bytes::new()),
                guest,
            )
            .await;
            opened.unwrap_or_else(|error| panic!("failed to open {func}: {error}"))
        }
    }

    fn block_on_test<F: std::future::Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap_or_else(|error| panic!("failed to build test runtime: {error}"))
            .block_on(future)
    }

    #[test]
    fn cancelling_a_partial_response_preserves_the_next_frame() {
        block_on_test(async {
            let mut peer = RawPeer::new();
            let (outgoing, mut incoming) = peer.open("cancelled", 1).await;
            let mut encoded = futures_lite::io::Cursor::new(Vec::new());
            super::write_frame(
                &mut encoded,
                &super::Frame::Data {
                    invocation: 1,
                    path: Vec::new(),
                    payload: "中文日本語한국어".as_bytes().to_vec(),
                },
            )
            .await
            .unwrap();
            let encoded = encoded.into_inner();
            let split = crate::wire::FRAME_MAGIC.len() + 2;
            futures_lite::io::AsyncWriteExt::write_all(&mut peer.write, &encoded[..split])
                .await
                .unwrap();
            let mut buffer = [0; 8];
            let mut read = Box::pin(incoming.read(&mut buffer));
            assert!(poll_once(&mut read).await.is_none());
            tokio::task::yield_now().await;
            drop(read);
            drop(incoming);
            drop(outgoing);
            futures_lite::io::AsyncWriteExt::write_all(&mut peer.write, &encoded[split..])
                .await
                .unwrap();
            let (_outgoing, mut incoming) = timeout(CONCURRENT_DEADLINE, peer.open("next", 2))
                .await
                .unwrap();
            super::write_frame(
                &mut peer.write,
                &super::Frame::Data {
                    invocation: 2,
                    path: Vec::new(),
                    payload: b"alive".to_vec(),
                },
            )
            .await
            .unwrap();
            super::write_frame(
                &mut peer.write,
                &super::Frame::Close {
                    invocation: 2,
                    path: Vec::new(),
                },
            )
            .await
            .unwrap();
            let mut response = Vec::new();
            timeout(CONCURRENT_DEADLINE, incoming.read_to_end(&mut response))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(response, b"alive");
        });
    }

    #[test]
    fn cancelling_a_partial_write_finishes_the_started_frame() {
        block_on_test(async {
            let mut peer = RawPeer::new();
            let (mut outgoing, incoming) = peer.open("cancelled", 1).await;
            let payload = vec![0x5a; RAW_UPLOAD_CHUNK_BYTES];
            let mut write = Box::pin(outgoing.write_all(&payload));
            assert!(poll_once(&mut write).await.is_none());
            tokio::task::yield_now().await;
            assert!(poll_once(&mut write).await.is_none());
            drop(write);
            drop(outgoing);
            drop(incoming);
            match timeout(CONCURRENT_DEADLINE, super::read_frame(&mut peer.read))
                .await
                .unwrap()
                .unwrap()
            {
                Some(super::Frame::Data {
                    invocation: 1,
                    payload: actual,
                    ..
                }) => assert_eq!(actual, payload),
                other => panic!("cancelled write left an incomplete frame: {other:?}"),
            }
            timeout(CONCURRENT_DEADLINE, peer.open("next", 2))
                .await
                .unwrap();
        });
    }

    #[test]
    fn a_driver_failure_preserves_the_guest_panic_report() {
        block_on_test(async {
            let mut peer = RawPeer::new();
            let client = peer.client.clone();
            let call = client.open_invocation("transport:test", "panic", Bytes::new());
            let guest = async {
                assert!(matches!(
                    super::read_frame(&mut peer.read).await.unwrap(),
                    Some(super::Frame::Open { .. })
                ));
                futures_lite::io::AsyncWriteExt::write_all(
                    &mut peer.write,
                    b"Kernel panic: cancellation test fault\n",
                )
                .await
                .unwrap();
            };
            let (result, ()) = timeout(CONCURRENT_DEADLINE, join(call, guest))
                .await
                .unwrap();
            let error = match result {
                Err(error) => error.to_string(),
                Ok(_) => panic!("a guest panic accepted the invocation"),
            };
            assert!(error.contains("cancellation test fault"), "{error}");
        });
    }

    #[test]
    fn stopping_the_driver_wakes_a_pending_invocation() {
        block_on_test(async {
            let (host, guest) = tokio::io::duplex(64);
            let (read, write) = tokio::io::split(host);
            let client = Client::new(read.compat(), write.compat_write());
            let driver = client.clone();
            let task = tokio::spawn(async move { driver.route_frames().await });
            let mut call =
                Box::pin(client.open_invocation("transport:test", "pending", Bytes::new()));
            assert!(poll_once(&mut call).await.is_none());
            tokio::task::yield_now().await;
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
            assert!(timeout(CONCURRENT_DEADLINE, call).await.unwrap().is_err());
            assert!(
                client
                    .open_invocation("transport:test", "closed", Bytes::new())
                    .await
                    .is_err()
            );
            drop(guest);
        });
    }

    fn fail_first_while_second_completes(
        frames: impl IntoIterator<Item = super::Frame>,
    ) -> (Vec<u8>, std::io::Error, (usize, usize)) {
        block_on_test(async {
            let mut peer = RawPeer::new();
            let (_first_out, mut first) = peer.open("first", 1).await;
            let (_second_out, mut second) = peer.open("second", 2).await;

            let RawPeer { write, .. } = &mut peer;
            let guest = async {
                for frame in frames.into_iter().chain([
                    super::Frame::Data {
                        invocation: 2,
                        path: Vec::new(),
                        payload: b"alive".to_vec(),
                    },
                    super::Frame::Close {
                        invocation: 2,
                        path: Vec::new(),
                    },
                ]) {
                    super::write_frame(write, &frame)
                        .await
                        .unwrap_or_else(|error| panic!("failed to write {frame:?}: {error}"));
                }
            };
            let mut answer = Vec::new();
            let consumer = timeout(CONCURRENT_DEADLINE, second.read_to_end(&mut answer));
            let ((), consumed) = join(guest, consumer).await;
            consumed
                .unwrap_or_else(|_| panic!("the second invocation never completed"))
                .unwrap_or_else(|error| panic!("the second invocation failed: {error}"));

            let error = first
                .read_to_end(&mut Vec::new())
                .await
                .expect_err("the flooded invocation must fail");
            let inbound = first.invocation.inbound.lock().await;
            let held = (
                inbound.chunks.len() + inbound.closed.len(),
                inbound.undelivered_bytes,
            );
            drop(inbound);
            (answer, error, held)
        })
    }

    #[test]
    fn a_flooded_path_fails_its_invocation_only() {
        let frames =
            (0..=MAX_UNDELIVERED_BYTES / RAW_UPLOAD_CHUNK_BYTES).map(|_| super::Frame::Data {
                invocation: 1,
                path: Vec::new(),
                payload: vec![0; RAW_UPLOAD_CHUNK_BYTES],
            });
        let (answer, error, held) = fail_first_while_second_completes(frames);
        assert_eq!(answer, b"alive");
        assert_eq!(
            WireError::from_io(&error),
            Some(&WireError::InboundBacklogExceeded {
                invocation: 1,
                held: MAX_UNDELIVERED_BYTES + RAW_UPLOAD_CHUNK_BYTES,
                max: MAX_UNDELIVERED_BYTES,
            })
        );
        assert_eq!(held, (0, 0), "a failed invocation releases what it held");
    }

    #[test]
    fn endless_data_paths_fail_their_invocation_only() {
        let frames = (0..1000_u32).map(|path| super::Frame::Data {
            invocation: 1,
            path: vec![path],
            payload: vec![1],
        });
        let (answer, error, held) = fail_first_while_second_completes(frames);
        assert_eq!(answer, b"alive");
        assert_eq!(
            WireError::from_io(&error),
            Some(&WireError::TooManyInboundPaths {
                invocation: 1,
                max: MAX_INBOUND_PATHS,
            })
        );
        assert_eq!(held, (0, 0), "a failed invocation releases what it held");
    }

    #[test]
    fn endless_close_paths_fail_their_invocation_only() {
        let frames = (0..1000_u32).map(|path| super::Frame::Close {
            invocation: 1,
            path: vec![path],
        });
        let (answer, error, held) = fail_first_while_second_completes(frames);
        assert_eq!(answer, b"alive");
        assert_eq!(
            WireError::from_io(&error),
            Some(&WireError::TooManyInboundPaths {
                invocation: 1,
                max: MAX_INBOUND_PATHS,
            })
        );
        assert_eq!(held, (0, 0), "a failed invocation releases what it held");
    }

    #[test]
    fn a_consumer_draining_at_its_own_pace_never_hits_the_bound() {
        block_on_test(async {
            let mut peer = RawPeer::new();
            let (_out, mut incoming) = peer.open("stream", 1).await;
            let chunks = 3 * MAX_UNDELIVERED_BYTES / RAW_UPLOAD_CHUNK_BYTES;

            let RawPeer { write, .. } = &mut peer;
            let guest = async {
                for _ in 0..chunks {
                    super::write_frame(
                        write,
                        &super::Frame::Data {
                            invocation: 1,
                            path: Vec::new(),
                            payload: vec![7; RAW_UPLOAD_CHUNK_BYTES],
                        },
                    )
                    .await
                    .unwrap_or_else(|error| panic!("failed to write a chunk: {error}"));
                }
                super::write_frame(
                    write,
                    &super::Frame::Close {
                        invocation: 1,
                        path: Vec::new(),
                    },
                )
                .await
                .unwrap_or_else(|error| panic!("failed to write the close: {error}"));
            };
            let consumer = async {
                let mut total = 0;
                let mut buffer = vec![0; RAW_UPLOAD_CHUNK_BYTES];
                loop {
                    let read = incoming
                        .read(&mut buffer)
                        .await
                        .unwrap_or_else(|error| panic!("the paced consumer failed: {error}"));
                    if read == 0 {
                        return total;
                    }
                    total += read;
                    tokio::task::yield_now().await;
                }
            };
            let ((), total) = timeout(CONCURRENT_DEADLINE * 6, join(guest, consumer))
                .await
                .unwrap_or_else(|_| panic!("the paced stream never completed"));
            assert_eq!(total, chunks * RAW_UPLOAD_CHUNK_BYTES);
        });
    }

    #[test]
    fn concurrent_subpaths_credit_flow_control_and_root_cancel_work() {
        block_on_test(async {
            let mut peer = RawPeer::new();
            let (guard, outgoing_root, incoming_root) = {
                let client = peer.client.clone();
                let open_fut =
                    client.open_cancellable_invocation("transport:test", "multi", Bytes::new());
                let accept_fut = async {
                    match super::read_frame(&mut peer.read).await.unwrap() {
                        Some(super::Frame::Open { invocation: 1, .. }) => {}
                        other => panic!("expected Open(1), got {other:?}"),
                    }
                    super::write_frame(&mut peer.write, &super::Frame::Accept { invocation: 1 })
                        .await
                        .unwrap();
                };
                let (res, ()) = join(open_fut, accept_fut).await;
                res.unwrap()
            };

            // Open two concurrent inbound sub-paths ([1] and [2]), [1] credit-gated with window 2.
            let sub_in_1_fut = incoming_root.subpath(1).with_credit_window(2);
            let expect_credit_fut = async {
                match super::read_frame(&mut peer.read).await.unwrap() {
                    Some(super::Frame::Credit {
                        invocation: 1,
                        path,
                        credits: 2,
                    }) => assert_eq!(path, vec![1]),
                    other => panic!("expected Credit(2) on [1], got {other:?}"),
                }
            };
            let (sub_in_1_res, ()) = join(sub_in_1_fut, expect_credit_fut).await;
            let mut sub_in_1 = sub_in_1_res.unwrap();
            let mut sub_in_2 = incoming_root.subpath(2);

            // Outbound credit-gated sub-path [3] parks until peer sends Credit.
            let mut sub_out_3 = outgoing_root.subpath(3).with_credits();
            let mut write_fut = Box::pin(sub_out_3.write_all(b"gated"));
            assert!(poll_once(&mut write_fut).await.is_none());

            super::write_frame(
                &mut peer.write,
                &super::Frame::Credit {
                    invocation: 1,
                    path: vec![3],
                    credits: 1,
                },
            )
            .await
            .unwrap();

            let (write_res, frame_read) = join(write_fut, super::read_frame(&mut peer.read)).await;
            write_res.unwrap();
            assert_eq!(
                frame_read.unwrap(),
                Some(super::Frame::Data {
                    invocation: 1,
                    path: vec![3],
                    payload: b"gated".to_vec(),
                })
            );

            // Interleaved inbound data on sub-paths [1] and [2].
            for frame in [
                super::Frame::Data {
                    invocation: 1,
                    path: vec![2],
                    payload: b"two".to_vec(),
                },
                super::Frame::Close {
                    invocation: 1,
                    path: vec![2],
                },
                super::Frame::Data {
                    invocation: 1,
                    path: vec![1],
                    payload: b"one-a".to_vec(),
                },
                super::Frame::Data {
                    invocation: 1,
                    path: vec![1],
                    payload: b"one-b".to_vec(),
                },
            ] {
                super::write_frame(&mut peer.write, &frame).await.unwrap();
            }

            let mut out2 = Vec::new();
            sub_in_2.read_to_end(&mut out2).await.unwrap();
            assert_eq!(out2, b"two");

            // Consuming from [1] replenishes credit.
            let mut buf1 = [0_u8; 5];
            let read_and_replenish = join(
                sub_in_1.read_exact(&mut buf1),
                super::read_frame(&mut peer.read),
            )
            .await;
            read_and_replenish.0.unwrap();
            assert_eq!(&buf1, b"one-a");
            assert_eq!(
                read_and_replenish.1.unwrap(),
                Some(super::Frame::Credit {
                    invocation: 1,
                    path: vec![1],
                    credits: 1,
                })
            );

            // Dropping the cancellation guard emits root Frame::Close { path: [] }.
            drop(guard);
            assert_eq!(
                timeout(CONCURRENT_DEADLINE, super::read_frame(&mut peer.read))
                    .await
                    .unwrap()
                    .unwrap(),
                Some(super::Frame::Close {
                    invocation: 1,
                    path: Vec::new(),
                })
            );
        });
    }
}
