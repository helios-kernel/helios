//! Typed error types for the inspector protocol.
//!
//! `anyhow` appears nowhere in this repository (AGENTS §3.2). Errors are
//! structured enums so every caller — the inspector, the CLI, the debugger
//! guest — dispatches on a stable contract instead of parsing a string, and
//! so a failure keeps the provenance of the layer that produced it.
//!
//! The transport's own tests drive [`crate::transport`] through the same
//! typed API a production caller uses, so there is no second error contract
//! reachable from this crate.

use std::io;

use thiserror::Error;

/// Lower-level transport faults raised by the framing client, server, and
/// peer-to-peer multiplexer.
#[derive(Debug, Error)]
pub enum TransportError {
    #[error("transport closed unexpectedly")]
    Closed,

    #[error("remote rejected invocation: {0}")]
    Rejected(String),

    #[error("server transport received unexpected reply frame")]
    UnexpectedReply,

    #[error("handler queue for {instance}.{func} was closed")]
    HandoffClosed { instance: String, func: String },

    #[error("transport I/O failed during {operation}: {source}")]
    Io {
        operation: &'static str,
        #[source]
        source: io::Error,
    },

    /// Remote peer reported a structured wire-protocol violation on an
    /// invocation or connection handle.
    #[error("wire protocol violation: {0}")]
    Wire(#[from] WireError),

    /// The guest's kernel printed a panic report on the console the
    /// frame scanner reads.
    ///
    /// A panicked guest answers no further frame, so without this the
    /// call in flight blocks until the caller's outer deadline: the
    /// benchmark lane that found it spent 2.5 h of a shared runner
    /// waiting on a kernel that had been dead for two seconds.
    #[error("guest kernel panicked: {report}")]
    GuestPanicked { report: String },
}

impl TransportError {
    pub fn io(operation: &'static str, source: io::Error) -> Self {
        if let Some(wire) = WireError::from_io(&source) {
            return Self::Wire(wire.clone());
        }
        Self::Io { operation, source }
    }

    /// Extracts a [`WireError`] when this transport fault originated from a
    /// wire-level limit or handle check.
    pub fn wire_error(&self) -> Option<&WireError> {
        match self {
            Self::Wire(error) => Some(error),
            Self::Io { source, .. } => WireError::from_io(source),
            Self::Closed
            | Self::Rejected(_)
            | Self::UnexpectedReply
            | Self::HandoffClosed { .. }
            | Self::GuestPanicked { .. } => None,
        }
    }

    /// The guest's panic report when this fault is a dead guest rather
    /// than a transport of its own.
    ///
    /// The walk is explicit because `io::Error` does not expose a
    /// custom payload through [`std::error::Error::source`], so an
    /// error chain alone cannot find a panic that crossed the framing
    /// layer.
    pub fn guest_panic(&self) -> Option<&str> {
        match self {
            Self::GuestPanicked { report } => Some(report),
            Self::Io { source, .. } => source
                .get_ref()
                .and_then(|inner| inner.downcast_ref::<Self>())
                .and_then(Self::guest_panic),
            Self::Closed
            | Self::Rejected(_)
            | Self::UnexpectedReply
            | Self::HandoffClosed { .. }
            | Self::Wire(_) => None,
        }
    }
}

impl From<TransportError> for io::Error {
    fn from(error: TransportError) -> Self {
        io::Error::other(error)
    }
}

/// Remote-procedure-call error covering encode, transport, and decode faults.
///
/// Service-level errors that the remote method itself reports (for example
/// `programs::ExecError`) are returned as nested `Result` values from the
/// caller-facing function rather than collapsed into this enum so each call
/// site keeps its typed service contract.
#[cfg(feature = "system")]
#[derive(Debug, Error)]
pub enum RpcError {
    #[error("failed to encode {instance}.{func} request: {source}")]
    Encode {
        instance: &'static str,
        func: &'static str,
        #[source]
        source: postcard::Error,
    },

    #[cfg(feature = "host")]
    #[error("failed to invoke {instance}.{func}: {source}")]
    Invoke {
        instance: &'static str,
        func: &'static str,
        #[source]
        source: TransportError,
    },

    #[error("failed to decode {instance}.{func} response: {source}")]
    Decode {
        instance: &'static str,
        func: &'static str,
        #[source]
        source: postcard::Error,
    },
}

#[cfg(feature = "system")]
impl RpcError {
    /// The guest's panic report when this call failed because the guest
    /// kernel died rather than because the call itself was refused.
    ///
    /// A caller that drives many calls in a row — the workload bench —
    /// uses it to stop instead of asking a dead guest the next question.
    pub fn guest_panic(&self) -> Option<&str> {
        match self {
            #[cfg(feature = "host")]
            Self::Invoke { source, .. } => source.guest_panic(),
            Self::Encode { .. } | Self::Decode { .. } => None,
        }
    }
}

/// Server-side dispatch error used by the in-debugger guest implementation.
///
/// Not gated on the `guest` feature: the RPC server loop that raises it
/// is generic over its dispatcher, and the host build tests that loop.
#[cfg(feature = "system")]
#[derive(Debug, Error)]
pub enum DispatchError {
    #[error("failed to encode {operation} response: {source}")]
    Encode {
        operation: &'static str,
        #[source]
        source: postcard::Error,
    },

    #[error("failed to decode {operation} request payload: {source}")]
    Decode {
        operation: &'static str,
        #[source]
        source: postcard::Error,
    },

    #[error("{operation} expects no request payload")]
    UnexpectedPayload { operation: &'static str },

    #[error("{message}")]
    Protocol { message: String },

    #[error("{0}")]
    Filesystem(String),

    #[error("transport I/O failed during {operation}: {source}")]
    Io {
        operation: &'static str,
        #[source]
        source: std::io::Error,
    },
}

#[cfg(feature = "system")]
impl DispatchError {
    pub fn protocol(message: impl Into<String>) -> Self {
        Self::Protocol {
            message: message.into(),
        }
    }
}

/// A frame, console line, stream credit update, or resource handle that
/// violates the wire protocol's limits or ownership rules.
///
/// Both peers treat incoming wire data as untrusted: every length, path
/// count, stream credit, and resource handle is validated before allocating
/// or dereferencing state. The low-level wire reader surfaces these through
/// `io::Error` (recoverable via [`WireError::from_io`]), while higher-level
/// RPC layers carry [`WireError`] directly.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum WireError {
    /// A frame header announced a payload above the frame maximum.
    #[error("frame payload of {len} bytes exceeds the {max}-byte maximum")]
    FrameTooLarge { len: usize, max: usize },

    /// A length-prefixed field announced more bytes than the frame still
    /// holds.
    #[error("{field} announces {len} elements needing {needed} bytes, but {remaining} remain")]
    LengthExceedsInput {
        field: &'static str,
        len: u32,
        needed: usize,
        remaining: usize,
    },

    /// The guest console produced more than the line maximum without a
    /// newline or a frame header.
    #[error("console line exceeds the {max}-byte maximum without a terminator")]
    ConsoleLineTooLong { max: usize },

    /// A peer sent one invocation more undelivered payload than the
    /// transport holds for it. Only that invocation fails.
    #[error(
        "invocation {invocation} would hold {held} undelivered bytes, over the {max}-byte maximum"
    )]
    InboundBacklogExceeded {
        invocation: u32,
        held: usize,
        max: usize,
    },

    /// A peer addressed more distinct paths on one invocation than the
    /// transport holds state for. Only that invocation fails.
    #[error("invocation {invocation} addressed more than the {max} inbound path(s) it may hold")]
    TooManyInboundPaths { invocation: u32, max: usize },

    /// A peer sent data on a sub-path stream or future without available
    /// credit.
    #[error("invocation {invocation} path {path:?} sent data without stream credit")]
    StreamCreditExceeded { invocation: u32, path: Vec<u32> },

    /// A peer sent zero credits or overflowed the 32-bit credit window on a
    /// sub-path.
    #[error("invocation {invocation} path {path:?} invalid credit grant of {credits}")]
    CreditOverflow {
        invocation: u32,
        path: Vec<u32>,
        credits: u32,
    },

    /// A peer referenced or dropped a connection-local resource handle that
    /// is unallocated, forged, or already dropped.
    #[error("invalid or forged connection resource handle {handle}")]
    InvalidResourceHandle { handle: u32 },

    /// A peer supplied a live resource handle whose runtime resource type
    /// does not match the parameter's WIT resource type.
    #[error("resource handle {handle} has type {actual}, expected {expected}")]
    ResourceTypeMismatch {
        handle: u32,
        expected: String,
        actual: String,
    },

    /// A peer attempted to drop or move (`own<R>`) a resource handle while an
    /// active `borrow<R>` is still in flight.
    #[error("resource handle {handle} cannot be moved or dropped while borrowed")]
    ResourceBorrowed { handle: u32 },

    /// A structured WIT-RPC payload failed validation or decoding.
    #[error("malformed WIT-RPC payload in {context}: {detail}")]
    MalformedPayload { context: String, detail: String },
}

impl WireError {
    /// The wire fault carried by `error`, if that is what it is.
    pub fn from_io(error: &io::Error) -> Option<&Self> {
        if let Some(direct) = error
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<Self>())
        {
            return Some(direct);
        }
        error
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<TransportError>())
            .and_then(TransportError::wire_error)
    }
}

impl From<WireError> for io::Error {
    fn from(error: WireError) -> Self {
        io::Error::new(io::ErrorKind::InvalidData, error)
    }
}
