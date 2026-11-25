use helios_inspector_protocol::{TransportError, WireError};
use thiserror::Error;

/// Result alias for WIT-RPC operations.
pub type Result<T> = core::result::Result<T, RpcError>;

/// Structured WIT-RPC error preserving wire and transport provenance.
#[derive(Debug, Error)]
pub enum RpcError {
    #[error("wire protocol violation: {0}")]
    Wire(#[source] WireError),

    #[error("transport failure: {0}")]
    Transport(#[source] TransportError),

    #[error("remote rejected invocation: {0}")]
    Rejected(String),

    #[error("stream closed by peer")]
    StreamClosed,

    #[error("remote future dropped without resolving a value")]
    FutureDropped,

    #[error("invocation cancelled")]
    Cancelled,
}

impl RpcError {
    /// Extracts the underlying [`WireError`] when the failure was caused by a
    /// wire limit, credit violation, or forged/invalid resource handle.
    pub fn wire_error(&self) -> Option<&WireError> {
        match self {
            Self::Wire(error) => Some(error),
            Self::Transport(error) => error.wire_error(),
            Self::Rejected(_) | Self::StreamClosed | Self::FutureDropped | Self::Cancelled => None,
        }
    }

    /// Extracts the guest kernel panic text if the failure originated from a
    /// panicked guest console.
    pub fn guest_panic(&self) -> Option<&str> {
        match self {
            Self::Transport(error) => error.guest_panic(),
            Self::Wire(_)
            | Self::Rejected(_)
            | Self::StreamClosed
            | Self::FutureDropped
            | Self::Cancelled => None,
        }
    }
}

impl From<WireError> for RpcError {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}

impl From<TransportError> for RpcError {
    fn from(error: TransportError) -> Self {
        match error {
            TransportError::Wire(wire) => Self::Wire(wire),
            TransportError::Rejected(message) => Self::Rejected(message),
            other => {
                if let Some(wire) = other.wire_error() {
                    return Self::Wire(wire.clone());
                }
                Self::Transport(other)
            }
        }
    }
}
