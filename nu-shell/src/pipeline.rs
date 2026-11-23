//! Asynchronous pipeline data representation for `helios-nu`.
//!
//! Bridges asynchronous bounded-channel streams (from external processes,
//! network responses, file watchers, and async stream stages) with Nushell's
//! synchronous [`PipelineData`] used by pure in-memory `nu-command` operators,
//! without ever calling `block_on`.

use nu_protocol::{
    ByteStream, ByteStreamType, ListStream, PipelineData, PipelineMetadata, ShellError, Signals,
    Span, Type, Value,
};

use crate::env::{AsyncByteReceiver, STREAM_CHANNEL_CAPACITY};

/// Data flowing between pipeline stages in [`crate::eval_ir_async`].
#[derive(Debug)]
pub enum AsyncPipelineData {
    /// No pipeline data.
    Empty,
    /// A materialized single [`Value`].
    Value(Value, Option<PipelineMetadata>),
    /// An asynchronous stream of structured [`Value`]s with bounded backpressure.
    ListStream {
        stream: async_channel::Receiver<Value>,
        span: Span,
        metadata: Option<PipelineMetadata>,
    },
    /// An asynchronous stream of raw bytes (text or binary) with optional exit status tracking.
    ByteStream {
        stream: AsyncByteReceiver,
        stderr: Option<AsyncByteReceiver>,
        exit_code: Option<async_channel::Receiver<Result<i32, crate::error::EnvError>>>,
        span: Span,
        stream_type: ByteStreamType,
        metadata: Option<PipelineMetadata>,
    },
    /// A synchronous [`PipelineData`] stream produced by a pure in-memory `nu-command` operator.
    Sync(PipelineData),
}

/// Register slot in the async IR evaluator, mirroring `PipelineExecutionData`.
#[derive(Debug)]
pub struct AsyncExecutionData {
    pub body: AsyncPipelineData,
    pub early_return: bool,
}

impl AsyncExecutionData {
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            body: AsyncPipelineData::Empty,
            early_return: false,
        }
    }

    #[must_use]
    pub const fn from_body(body: AsyncPipelineData) -> Self {
        Self {
            body,
            early_return: false,
        }
    }

    #[must_use]
    pub const fn with_early_return(mut self) -> Self {
        self.early_return = true;
        self
    }

    #[must_use]
    pub fn span(&self) -> Option<Span> {
        self.body.span()
    }
}

impl From<AsyncPipelineData> for AsyncExecutionData {
    fn from(body: AsyncPipelineData) -> Self {
        Self::from_body(body)
    }
}

impl From<PipelineData> for AsyncPipelineData {
    fn from(data: PipelineData) -> Self {
        match data {
            PipelineData::Empty => Self::Empty,
            PipelineData::Value(val, meta) => Self::Value(val, meta),
            other @ (PipelineData::ListStream(..) | PipelineData::ByteStream(..)) => {
                Self::Sync(other)
            }
        }
    }
}

impl AsyncPipelineData {
    #[must_use]
    pub const fn empty() -> Self {
        Self::Empty
    }

    #[must_use]
    pub fn value(val: Value, metadata: impl Into<Option<PipelineMetadata>>) -> Self {
        Self::Value(val, metadata.into())
    }

    #[must_use]
    pub fn list_stream(
        stream: async_channel::Receiver<Value>,
        span: Span,
        metadata: impl Into<Option<PipelineMetadata>>,
    ) -> Self {
        Self::ListStream {
            stream,
            span,
            metadata: metadata.into(),
        }
    }

    #[must_use]
    pub fn byte_stream(
        stream: AsyncByteReceiver,
        span: Span,
        stream_type: ByteStreamType,
        metadata: impl Into<Option<PipelineMetadata>>,
    ) -> Self {
        Self::ByteStream {
            stream,
            stderr: None,
            exit_code: None,
            span,
            stream_type,
            metadata: metadata.into(),
        }
    }

    #[must_use]
    pub fn span(&self) -> Option<Span> {
        match self {
            Self::Empty => None,
            Self::Value(val, _) => Some(val.span()),
            Self::ListStream { span, .. } | Self::ByteStream { span, .. } => Some(*span),
            Self::Sync(data) => data.span(),
        }
    }

    #[must_use]
    pub fn metadata_ref(&self) -> Option<&PipelineMetadata> {
        match self {
            Self::Empty => None,
            Self::Value(_, meta)
            | Self::ListStream { metadata: meta, .. }
            | Self::ByteStream { metadata: meta, .. } => meta.as_ref(),
            Self::Sync(data) => data.metadata_ref(),
        }
    }

    pub fn take_metadata(&mut self) -> Option<PipelineMetadata> {
        match self {
            Self::Empty => None,
            Self::Value(_, meta)
            | Self::ListStream { metadata: meta, .. }
            | Self::ByteStream { metadata: meta, .. } => meta.take(),
            Self::Sync(data) => data.take_metadata(),
        }
    }

    #[must_use]
    pub fn with_span(self, span: Span) -> Self {
        match self {
            Self::Empty => Self::Value(Value::nothing(span), None),
            Self::Value(val, meta) => Self::Value(val.with_span(span), meta),
            Self::ListStream {
                stream, metadata, ..
            } => Self::ListStream {
                stream,
                span,
                metadata,
            },
            Self::ByteStream {
                stream,
                stderr,
                exit_code,
                stream_type,
                metadata,
                ..
            } => Self::ByteStream {
                stream,
                stderr,
                exit_code,
                span,
                stream_type,
                metadata,
            },
            Self::Sync(data) => Self::Sync(data.with_span(span)),
        }
    }

    #[must_use]
    pub fn is_empty_or_nothing(&self) -> bool {
        matches!(
            self,
            Self::Empty
                | Self::Value(Value::Nothing { .. }, _)
                | Self::Sync(PipelineData::Empty | PipelineData::Value(Value::Nothing { .. }, _))
        )
    }

    #[must_use]
    pub fn get_type(&self) -> Type {
        match self {
            Self::Empty => Type::Nothing,
            Self::Value(val, _) => val.get_type(),
            Self::ListStream { .. } => Type::list(Type::Any),
            Self::ByteStream { stream_type, .. } => (*stream_type).into(),
            Self::Sync(data) => data.get_type(),
        }
    }

    /// Collect this pipeline data into a materialized [`Value`] asynchronously.
    pub async fn into_value_async(self, fallback_span: Span) -> Result<Value, ShellError> {
        match self {
            Self::Empty => Ok(Value::nothing(fallback_span)),
            Self::Value(val, _) => {
                if val.span() == Span::unknown() {
                    Ok(val.with_span(fallback_span))
                } else {
                    Ok(val)
                }
            }
            Self::ListStream { stream, span, .. } => {
                let mut values = Vec::new();
                while let Ok(item) = stream.recv().await {
                    if let Value::Error { error, .. } = item {
                        return Err(*error);
                    }
                    values.push(item);
                }
                Ok(Value::list(values, span))
            }
            Self::ByteStream {
                stream,
                exit_code,
                span,
                stream_type,
                ..
            } => {
                let bytes = collect_byte_receiver(stream).await?;
                if let Some(exit_rx) = exit_code {
                    let _ = exit_rx.recv().await;
                }
                Ok(bytes_to_value(bytes, stream_type, span))
            }
            Self::Sync(data) => data.into_value(fallback_span),
        }
    }

    /// Collect bytes from this pipeline data asynchronously (for `save`, redirections, HTTP bodies).
    pub async fn into_bytes_async(self, fallback_span: Span) -> Result<Vec<u8>, ShellError> {
        match self {
            Self::Empty => Ok(Vec::new()),
            Self::Value(val, _) => value_to_bytes(&val, fallback_span),
            Self::ByteStream {
                stream, exit_code, ..
            } => {
                let bytes = collect_byte_receiver(stream).await?;
                if let Some(exit_rx) = exit_code {
                    let _ = exit_rx.recv().await;
                }
                Ok(bytes)
            }
            Self::ListStream { stream, .. } => {
                let mut out = Vec::new();
                while let Ok(item) = stream.recv().await {
                    if let Value::Error { error, .. } = item {
                        return Err(*error);
                    }
                    let chunk = value_to_bytes(&item, fallback_span)?;
                    out.extend_from_slice(&chunk);
                    if !out.ends_with(b"\n") {
                        out.push(b'\n');
                    }
                }
                Ok(out)
            }
            Self::Sync(data) => {
                let mut buf = Vec::new();
                data.write_to(&mut buf)?;
                Ok(buf)
            }
        }
    }

    /// Convert this pipeline data into an asynchronous byte receiver without
    /// buffering an already-streaming `ByteStream`.
    #[must_use]
    pub fn into_byte_receiver(self, fallback_span: Span) -> Option<AsyncByteReceiver> {
        match self {
            Self::Empty => None,
            Self::ByteStream { stream, .. } => Some(stream),
            Self::Value(val, _) => {
                let (tx, rx) = async_channel::bounded(1);
                let result = value_to_bytes(&val, fallback_span);
                let _ = tx.try_send(result);
                Some(rx)
            }
            Self::ListStream { .. } | Self::Sync(_) => {
                // Handled by caller via `into_byte_receiver_async` when draining streams.
                None
            }
        }
    }

    /// Convert any pipeline data into an [`AsyncByteReceiver`] asynchronously.
    /// Existing [`Self::ByteStream`] receivers pass straight through with zero buffering.
    pub async fn into_byte_receiver_async(
        self,
        fallback_span: Span,
    ) -> Result<Option<AsyncByteReceiver>, ShellError> {
        match self {
            Self::Empty => Ok(None),
            Self::ByteStream { stream, .. } => Ok(Some(stream)),
            other => {
                let bytes = other.into_bytes_async(fallback_span).await?;
                let (tx, rx) = async_channel::bounded(1);
                let _ = tx.send(Ok(bytes)).await;
                Ok(Some(rx))
            }
        }
    }

    /// Convert async pipeline data into synchronous [`PipelineData`] before
    /// dispatching into a pure in-memory `nu-command` operator.
    pub async fn into_sync_pipeline_data(
        self,
        _fallback_span: Span,
    ) -> Result<PipelineData, ShellError> {
        match self {
            Self::Empty => Ok(PipelineData::empty()),
            Self::Value(val, meta) => Ok(PipelineData::value(val, meta)),
            Self::Sync(data) => Ok(data),
            Self::ListStream {
                stream,
                span,
                metadata,
            } => {
                let mut items = Vec::new();
                while let Ok(item) = stream.recv().await {
                    if let Value::Error { error, .. } = item {
                        return Err(*error);
                    }
                    items.push(item);
                }
                Ok(PipelineData::list_stream(
                    ListStream::new(items.into_iter(), span, Signals::EMPTY),
                    metadata,
                ))
            }
            Self::ByteStream {
                stream,
                exit_code,
                span,
                stream_type,
                metadata,
                ..
            } => {
                let bytes = collect_byte_receiver(stream).await?;
                if let Some(exit_rx) = exit_code {
                    let _ = exit_rx.recv().await;
                }
                let byte_stream = match stream_type {
                    ByteStreamType::Binary => ByteStream::read_binary(bytes, span, Signals::EMPTY),
                    ByteStreamType::String => match String::from_utf8(bytes) {
                        Ok(s) => ByteStream::read_string(s, span, Signals::EMPTY),
                        Err(err) => ByteStream::read_binary(err.into_bytes(), span, Signals::EMPTY),
                    },
                    ByteStreamType::Unknown => match String::from_utf8(bytes) {
                        Ok(s) => ByteStream::read_string(s, span, Signals::EMPTY),
                        Err(err) => ByteStream::read_binary(err.into_bytes(), span, Signals::EMPTY),
                    },
                };
                Ok(PipelineData::byte_stream(byte_stream, metadata))
            }
        }
    }

    /// Pull the next value from this pipeline data if it is a stream, or convert
    /// it into a streamable representation for `Instruction::Iterate`.
    pub async fn into_list_stream_receiver(
        self,
        fallback_span: Span,
    ) -> Result<
        (
            async_channel::Receiver<Value>,
            Span,
            Option<PipelineMetadata>,
        ),
        ShellError,
    > {
        match self {
            Self::ListStream {
                stream,
                span,
                metadata,
            } => Ok((stream, span, metadata)),
            Self::Empty => {
                let (_, rx) = async_channel::bounded(1);
                Ok((rx, fallback_span, None))
            }
            Self::Value(val, metadata) => {
                let span = val.span();
                let items: Vec<Value> = match val {
                    Value::List { vals, .. } => vals.into_owned(),
                    Value::Range { val: range, .. } => {
                        range.into_range_iter(span, Signals::EMPTY).collect()
                    }
                    Value::Nothing { .. } => Vec::new(),
                    other => vec![other],
                };
                let cap = items.len().clamp(1, STREAM_CHANNEL_CAPACITY);
                let (tx, rx) = async_channel::bounded(cap);
                // Bounded push: if items fit in cap, push synchronously without spawning;
                // otherwise use unbounded channel to avoid deadlocking a single-task puller.
                if items.len() <= cap {
                    for item in items {
                        let _ = tx.try_send(item);
                    }
                    Ok((rx, span, metadata))
                } else {
                    let (tx, rx) = async_channel::unbounded();
                    for item in items {
                        let _ = tx.try_send(item);
                    }
                    Ok((rx, span, metadata))
                }
            }
            Self::Sync(mut data) => {
                let span = data.span().unwrap_or(fallback_span);
                let metadata = data.take_metadata();
                let items: Vec<Value> = data.into_iter().collect();
                let (tx, rx) = async_channel::unbounded();
                for item in items {
                    let _ = tx.try_send(item);
                }
                Ok((rx, span, metadata))
            }
            Self::ByteStream {
                stream,
                exit_code,
                span,
                stream_type,
                metadata,
                ..
            } => {
                let bytes = collect_byte_receiver(stream).await?;
                if let Some(exit_rx) = exit_code {
                    let _ = exit_rx.recv().await;
                }
                let val = bytes_to_value(bytes, stream_type, span);
                let (tx, rx) = async_channel::bounded(1);
                let _ = tx.try_send(val);
                Ok((rx, span, metadata))
            }
        }
    }

    /// Drain this pipeline data, returning any embedded error and last exit code.
    pub async fn drain_async(self) -> Result<Option<i32>, ShellError> {
        match self {
            Self::Empty | Self::Value(_, _) => Ok(None),
            Self::ListStream { stream, .. } => {
                while let Ok(item) = stream.recv().await {
                    if let Value::Error { error, .. } = item {
                        return Err(*error);
                    }
                }
                Ok(None)
            }
            Self::ByteStream {
                stream,
                stderr,
                exit_code,
                span,
                ..
            } => {
                while let Ok(chunk) = stream.recv().await {
                    let _ = chunk?;
                }
                if let Some(stderr_rx) = stderr {
                    while let Ok(chunk) = stderr_rx.recv().await {
                        let _ = chunk?;
                    }
                }
                if let Some(exit_rx) = exit_code
                    && let Ok(code) = exit_rx.recv().await
                {
                    let code =
                        code.map_err(|err| err.into_shell_error("external command failed", span))?;
                    return Ok(Some(code));
                }
                Ok(None)
            }
            Self::Sync(data) => {
                data.drain()?;
                Ok(None)
            }
        }
    }
}

/// Collect all chunks from an [`AsyncByteReceiver`] into a single `Vec<u8>`.
pub async fn collect_byte_receiver(rx: AsyncByteReceiver) -> Result<Vec<u8>, ShellError> {
    let mut bytes = Vec::new();
    while let Ok(chunk) = rx.recv().await {
        bytes.extend_from_slice(&chunk?);
    }
    Ok(bytes)
}

/// Convert raw bytes to a Nushell [`Value`] honoring [`ByteStreamType`].
#[must_use]
pub fn bytes_to_value(bytes: Vec<u8>, stream_type: ByteStreamType, span: Span) -> Value {
    match stream_type {
        ByteStreamType::Binary => Value::binary(bytes, span),
        ByteStreamType::String | ByteStreamType::Unknown => match String::from_utf8(bytes) {
            Ok(text) => Value::string(text, span),
            Err(err) => Value::binary(err.into_bytes(), span),
        },
    }
}

/// Convert a Nushell [`Value`] to bytes suitable for file writing, redirection, or external stdin.
pub fn value_to_bytes(val: &Value, span: Span) -> Result<Vec<u8>, ShellError> {
    match val {
        Value::Nothing { .. } => Ok(Vec::new()),
        Value::String { val, .. } => Ok(val.as_bytes().to_vec()),
        Value::Binary { val, .. } => Ok(val.to_vec()),
        Value::Error { error, .. } => Err(*error.clone()),
        other => Ok(other
            .to_abbreviated_string(&nu_protocol::Config::default())
            .into_bytes()),
    }
    .map_err(|err| match err {
        ShellError::Io(_) => err,
        other => {
            let _ = span;
            other
        }
    })
}
