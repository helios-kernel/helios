use std::future::Future;

use futures_io::{AsyncRead, AsyncWrite};
use helios_inspector_protocol::WireError;
use helios_inspector_protocol::mux::{
    DEFAULT_STREAM_CREDIT_WINDOW, InboundCall, MaybeSend, MaybeSync, MuxConfig, MuxDispatcher,
    MuxDriverChannels, PeerHandle, create_mux, drive_mux,
};

use crate::codec::{RpcDecode, RpcEncode, decode_server_request, encode_server_response};
use crate::error::RpcError;
use crate::resource::{HandleAllocator, ResourceEntry, ResourceTable};

/// Configuration for an [`Endpoint`].
#[derive(Debug, Clone, Copy)]
pub struct EndpointConfig {
    /// Per-stream credit window granted to remote `stream<T>` writers.
    pub stream_credit_window: u32,
}

impl Default for EndpointConfig {
    fn default() -> Self {
        Self {
            stream_credit_window: DEFAULT_STREAM_CREDIT_WINDOW,
        }
    }
}

/// Context passed to a generated [`Dispatcher`] for each accepted incoming
/// invocation.
pub struct ServerInvocation<'a, R: ResourceEntry> {
    call: InboundCall,
    resources: &'a ResourceTable<R>,
}

impl<'a, R: ResourceEntry> ServerInvocation<'a, R> {
    pub fn peer(&self) -> &PeerHandle {
        self.call.peer()
    }

    pub fn resources(&self) -> &'a ResourceTable<R> {
        self.resources
    }

    pub fn is_cancelled(&self) -> bool {
        self.call.is_cancelled()
    }

    pub async fn decode_request<T: RpcDecode<R>>(&self) -> Result<T, WireError> {
        let raw = self
            .call
            .recv_root_request()
            .await
            .map_err(|err| match err.wire_error() {
                Some(wire) => wire.clone(),
                None => WireError::MalformedPayload {
                    context: "recv_root_request".to_owned(),
                    detail: err.to_string(),
                },
            })?;
        decode_server_request(&self.call, self.resources, &raw).await
    }

    pub async fn encode_response<T: RpcEncode<R>>(&self, value: T) -> Result<(), WireError> {
        let bytes = encode_server_response(&self.call, self.resources, value).await?;
        let _ = self.call.send_root_response(&bytes).await;
        Ok(())
    }
}

/// Server-side WIT interface router contract implemented by generated
/// `Server<H>` adapters.
pub trait Dispatcher: MaybeSend + MaybeSync + 'static {
    type Resource: ResourceEntry;

    fn supports(&self, instance: &str, func: &str) -> bool;

    fn dispatch<'a>(
        &'a self,
        ctx: ServerInvocation<'a, Self::Resource>,
        instance: &'a str,
        func: &'a str,
    ) -> impl Future<Output = Result<(), WireError>> + MaybeSend + 'a;
}

/// Composable service set bound to a connection's shared [`HandleAllocator`].
///
/// Implemented automatically for `()`, every [`Dispatcher`], and `(A, B)` pairs
/// so multiple generated interface servers (including ones exporting stateful
/// resources) compose on one [`Endpoint`] with zero dynamic dispatch.
pub trait Service: MaybeSend + MaybeSync + 'static {
    type Bound: MuxDispatcher;

    fn bind(self, allocator: &HandleAllocator) -> Self::Bound;
}

pub struct EmptyBoundService;

impl MuxDispatcher for EmptyBoundService {
    fn supports(&self, _instance: &str, _func: &str) -> bool {
        false
    }

    async fn dispatch(
        &self,
        _call: InboundCall,
        instance: String,
        func: String,
    ) -> Result<(), WireError> {
        Err(WireError::MalformedPayload {
            context: "EmptyBoundService".to_owned(),
            detail: format!("unhandled invocation {instance}.{func}"),
        })
    }

    async fn drop_resource(&self, handle: u32) -> Result<(), WireError> {
        Err(WireError::InvalidResourceHandle { handle })
    }

    async fn on_disconnect(&self) {}
}

impl Service for () {
    type Bound = EmptyBoundService;

    fn bind(self, _allocator: &HandleAllocator) -> Self::Bound {
        EmptyBoundService
    }
}

pub struct BoundDispatcher<D: Dispatcher> {
    dispatcher: D,
    resources: ResourceTable<D::Resource>,
}

impl<D: Dispatcher> BoundDispatcher<D> {
    pub fn resources(&self) -> &ResourceTable<D::Resource> {
        &self.resources
    }
}

impl<D: Dispatcher> MuxDispatcher for BoundDispatcher<D> {
    fn supports(&self, instance: &str, func: &str) -> bool {
        self.dispatcher.supports(instance, func)
    }

    async fn dispatch(
        &self,
        call: InboundCall,
        instance: String,
        func: String,
    ) -> Result<(), WireError> {
        let ctx = ServerInvocation {
            call,
            resources: &self.resources,
        };
        self.dispatcher.dispatch(ctx, &instance, &func).await
    }

    async fn drop_resource(&self, handle: u32) -> Result<(), WireError> {
        tracing::trace!(handle, "dropping connection-scoped WIT-RPC resource");
        self.resources.drop_handle(handle).await
    }

    async fn on_disconnect(&self) {
        let dropped = self.resources.clear().await;
        if dropped > 0 {
            tracing::debug!(
                dropped,
                "cleaned up live WIT-RPC resources on transport disconnect"
            );
        }
    }
}

impl<D: Dispatcher> Service for D {
    type Bound = BoundDispatcher<D>;

    fn bind(self, allocator: &HandleAllocator) -> Self::Bound {
        BoundDispatcher {
            dispatcher: self,
            resources: ResourceTable::with_allocator(allocator.clone()),
        }
    }
}

pub struct BoundPair<A, B> {
    left: A,
    right: B,
}

impl<A: MuxDispatcher, B: MuxDispatcher> MuxDispatcher for BoundPair<A, B> {
    fn supports(&self, instance: &str, func: &str) -> bool {
        self.left.supports(instance, func) || self.right.supports(instance, func)
    }

    async fn dispatch(
        &self,
        call: InboundCall,
        instance: String,
        func: String,
    ) -> Result<(), WireError> {
        if self.left.supports(&instance, &func) {
            self.left.dispatch(call, instance, func).await
        } else {
            self.right.dispatch(call, instance, func).await
        }
    }

    async fn drop_resource(&self, handle: u32) -> Result<(), WireError> {
        match self.left.drop_resource(handle).await {
            Ok(()) => Ok(()),
            Err(WireError::InvalidResourceHandle { .. }) => self.right.drop_resource(handle).await,
            Err(other) => Err(other),
        }
    }

    async fn on_disconnect(&self) {
        futures_lite::future::zip(self.left.on_disconnect(), self.right.on_disconnect()).await;
    }
}

impl<A: Service, B: Service> Service for (A, B) {
    type Bound = BoundPair<A::Bound, B::Bound>;

    fn bind(self, allocator: &HandleAllocator) -> Self::Bound {
        BoundPair {
            left: self.0.bind(allocator),
            right: self.1.bind(allocator),
        }
    }
}

/// Symmetric peer-to-peer WIT-RPC connection over any `AsyncRead + AsyncWrite`
/// byte stream.
pub struct Endpoint<R, W, S: Service> {
    read: R,
    write: W,
    peer: PeerHandle,
    channels: MuxDriverChannels,
    bound: S::Bound,
}

impl<R, W, S> Endpoint<R, W, S>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    S: Service,
{
    /// Constructs a new symmetric RPC endpoint with default configuration.
    pub fn new(read: R, write: W, service: S) -> Self {
        Self::with_config(read, write, service, EndpointConfig::default())
    }

    /// Constructs a new symmetric RPC endpoint with explicit configuration.
    pub fn with_config(read: R, write: W, service: S, config: EndpointConfig) -> Self {
        let mux_config = MuxConfig {
            stream_credit_window: config.stream_credit_window.max(1),
            ..MuxConfig::default()
        };
        let (peer, channels) = create_mux(mux_config);
        let allocator = HandleAllocator::new();
        let bound = service.bind(&allocator);
        Self {
            read,
            write,
            peer,
            channels,
            bound,
        }
    }

    /// Returns a cloneable [`PeerHandle`] for constructing generated WIT-RPC
    /// clients on this connection.
    pub fn handle(&self) -> PeerHandle {
        self.peer.clone()
    }

    /// Drives bidirectional RPC framing, concurrent incoming invocations,
    /// stream credit updates, cancellations, and disconnect resource cleanup
    /// until the transport closes.
    pub async fn drive(self) -> Result<(), RpcError> {
        let Self {
            read,
            write,
            peer: _,
            channels,
            bound,
        } = self;
        drive_mux(read, write, channels, &bound)
            .await
            .map_err(RpcError::from)
    }
}

impl<R, W, D> Endpoint<R, W, D>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    D: Dispatcher,
{
    /// Borrows the connection's exported [`ResourceTable`] when serving a
    /// single [`Dispatcher`].
    pub fn resources(&self) -> &ResourceTable<D::Resource> {
        self.bound.resources()
    }
}
