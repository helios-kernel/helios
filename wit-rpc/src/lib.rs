//! Transparent async WIT-RPC runtime with symmetric peer-to-peer framing,
//! credit-controlled multi-path `stream<T>` / `future<T>` channels, caller
//! cancellation propagation, and connection-scoped `ResourceTable` handles.
//!
//! Compiles identically on host (`std`) and `wasm32-wasip3` guest targets
//! over any `futures_io::AsyncRead + futures_io::AsyncWrite` byte stream.

mod codec;
mod endpoint;
mod error;
#[cfg(feature = "inspector-rpc")]
pub mod inspector;
#[cfg(feature = "inspector-rpc")]
pub mod inspector_fs;
#[cfg(feature = "inspector-rpc")]
pub mod inspector_snapshot;
mod resource;
mod stream;

pub use codec::{Decoder, Encoder, ErrorContext, RpcDecode, RpcEncode};
pub use endpoint::{Dispatcher, Endpoint, EndpointConfig, ServerInvocation, Service};
pub use error::{Result, RpcError};
pub use helios_inspector_protocol::mux::{
    DEFAULT_STREAM_CREDIT_WINDOW, MaybeSend, MaybeSync, PeerHandle,
};
pub use helios_inspector_protocol::{TransportError, WireError};
pub use helios_wit_rpc_macro::generate;
pub use resource::{
    EitherResource, HandleAllocator, RemoteResource, ResourceBorrow, ResourceEntry,
    ResourceSlotAccess, ResourceTable, ResourceTableInner,
};
pub use stream::{FutureReader, FutureWriter, StreamReader, StreamWriter, future, stream};

/// Support helpers addressed by code emitted from [`generate!`].
#[doc(hidden)]
pub mod __private {
    pub use crate::codec::{
        Decoder, Encoder, PendingInboundSubpath, PendingOutboundSubpath, RpcDecode, RpcEncode,
        activate_inbound_subpaths, activate_outbound_subpaths, decode_client_value,
        encode_client_value,
    };
    pub use crate::endpoint::{Dispatcher, ServerInvocation, Service};
    pub use crate::error::{Result, RpcError};
    pub use crate::resource::{
        RemoteResource, ResourceBorrow, ResourceEntry, ResourceSlotAccess, ResourceTable,
        ResourceTableInner,
    };
    pub use crate::stream::{FutureReader, StreamReader};
    pub use helios_inspector_protocol::WireError;
    pub use helios_inspector_protocol::mux::{MaybeSend, MaybeSync, PeerHandle};
}
