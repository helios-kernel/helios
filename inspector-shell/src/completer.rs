//! Asynchronous `reedline 0.53.0` completer, Nushell syntax highlighter, and
//! multiline validator with zero `block_on`.
//!
//! [`AsyncReedlineCompleter`] bridges `reedline`'s non-blocking
//! [`CompletionResult::Pending`] / [`Completer::poll_completion`] protocol to
//! an async background worker task calling [`helios_nu::complete_async`] over
//! the live cached [`HeliosEnv`].

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use helios_nu::{CompletionItem, CompletionKind, HeliosEnv, complete_async};
use nu_ansi_term::{Color, Style};
use nu_parser::{FlatShape, flatten_block};
use nu_protocol::engine::{EngineState, Stack, StateWorkingSet};
use reedline::{
    Completer, CompletionOrigin, CompletionResult, CompletionStatus, Highlighter, RepaintSignal,
    Span as ReedlineSpan, StyledText, Suggestion, Suggestions, ValidationResult, Validator,
};
use tokio::sync::RwLock;

/// Shared snapshot of the shell's [`EngineState`] and [`Stack`] read by the
/// background async completion worker.
#[derive(Clone)]
pub struct CompletionSnapshot {
    pub engine_state: EngineState,
    pub stack: Stack,
}

/// Request sent non-blockingly from `reedline` to the async completion worker.
#[derive(Debug, Clone)]
pub struct CompletionRequest {
    pub id: u64,
    pub line: String,
    pub pos: usize,
}

/// Response delivered back from the async completion worker.
#[derive(Debug, Clone)]
pub struct CompletionResponse {
    pub id: u64,
    pub line: String,
    pub pos: usize,
    pub suggestions: Suggestions,
}

/// Spawn the async completion worker task on the current Tokio runtime.
///
/// Consumes [`CompletionRequest`]s from `req_rx`, evaluates
/// [`helios_nu::complete_async`] with zero `block_on`, publishes the result
/// on `resp_tx`, and triggers `repaint` so `reedline` refreshes immediately.
pub fn spawn_completion_worker<E>(
    env: E,
    snapshot: Arc<RwLock<CompletionSnapshot>>,
    req_rx: async_channel::Receiver<CompletionRequest>,
    resp_tx: async_channel::Sender<CompletionResponse>,
    repaint: Option<RepaintSignal>,
) -> tokio::task::JoinHandle<()>
where
    E: HeliosEnv + 'static,
{
    tokio::spawn(async move {
        while let Ok(mut req) = req_rx.recv().await {
            // Coalesce queued requests so only the latest cursor state is resolved.
            while let Ok(newer) = req_rx.try_recv() {
                req = newer;
            }
            let snap = snapshot.read().await.clone();
            let items =
                complete_async(&snap.engine_state, &snap.stack, &env, &req.line, req.pos).await;
            let suggestions: Suggestions = items.into_iter().map(item_to_suggestion).collect();
            let response = CompletionResponse {
                id: req.id,
                line: req.line,
                pos: req.pos,
                suggestions,
            };
            if resp_tx.send(response).await.is_err() {
                break;
            }
            if let Some(sig) = &repaint {
                sig.request_repaint();
            }
        }
    })
}

/// Convert a [`helios_nu::CompletionItem`] into a `reedline::Suggestion`.
#[must_use]
pub fn item_to_suggestion(item: CompletionItem) -> Suggestion {
    let append_whitespace = match item.kind {
        CompletionKind::Path => !item.value.ends_with('/'),
        CompletionKind::InspectKey => false,
        CompletionKind::Command
        | CompletionKind::Flag
        | CompletionKind::Column
        | CompletionKind::Moniker
        | CompletionKind::DiagnosticTarget
        | CompletionKind::OciRef
        | CompletionKind::Variable => true,
    };
    let style = match item.kind {
        CompletionKind::Command => Some(Style::new().fg(Color::Cyan).bold()),
        CompletionKind::Flag => Some(Style::new().fg(Color::Yellow)),
        CompletionKind::Column => Some(Style::new().fg(Color::Green)),
        CompletionKind::InspectKey => Some(Style::new().fg(Color::Magenta)),
        CompletionKind::Moniker | CompletionKind::DiagnosticTarget => {
            Some(Style::new().fg(Color::Blue))
        }
        CompletionKind::Path => Some(Style::new().fg(Color::LightCyan)),
        CompletionKind::OciRef | CompletionKind::Variable => Some(Style::new().fg(Color::Purple)),
    };
    Suggestion {
        value: item.value,
        display_override: None,
        description: (!item.description.is_empty()).then_some(item.description),
        style,
        extra: None,
        span: ReedlineSpan::new(item.replace_start, item.replace_end),
        append_whitespace,
        match_indices: None,
    }
}

/// Non-blocking `reedline::Completer` driving [`helios_nu::complete_async`] via
/// bounded channels (zero `block_on`).
pub struct AsyncReedlineCompleter {
    req_tx: async_channel::Sender<CompletionRequest>,
    resp_rx: async_channel::Receiver<CompletionResponse>,
    next_id: AtomicU64,
    in_flight: Option<(u64, String, usize)>,
    last_ready: Option<CompletionResponse>,
}

impl AsyncReedlineCompleter {
    /// Construct a new [`AsyncReedlineCompleter`] paired with the channel ends
    /// for [`spawn_completion_worker`].
    #[must_use]
    pub fn channel_pair() -> (
        Self,
        async_channel::Receiver<CompletionRequest>,
        async_channel::Sender<CompletionResponse>,
    ) {
        let (req_tx, req_rx) = async_channel::bounded(8);
        let (resp_tx, resp_rx) = async_channel::bounded(4);
        let completer = Self {
            req_tx,
            resp_rx,
            next_id: AtomicU64::new(1),
            in_flight: None,
            last_ready: None,
        };
        (completer, req_rx, resp_tx)
    }

    fn drain_responses(&mut self) -> bool {
        let mut received_any = false;
        while let Ok(resp) = self.resp_rx.try_recv() {
            if self
                .in_flight
                .as_ref()
                .is_some_and(|(id, _, _)| *id == resp.id)
            {
                self.in_flight = None;
            }
            self.last_ready = Some(resp);
            received_any = true;
        }
        received_any
    }
}

impl Completer for AsyncReedlineCompleter {
    fn complete(&mut self, line: &str, pos: usize) -> CompletionResult {
        self.drain_responses();

        if let Some(ready) = &self.last_ready
            && ready.line == line
            && ready.pos == pos
        {
            return CompletionResult::Fresh {
                suggestions: Arc::clone(&ready.suggestions),
                partial: None,
            };
        }

        let already_requested = self
            .in_flight
            .as_ref()
            .is_some_and(|(_, req_line, req_pos)| req_line == line && *req_pos == pos);

        if !already_requested {
            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            let req = CompletionRequest {
                id,
                line: line.to_owned(),
                pos,
            };
            let _ = self.req_tx.try_send(req);
            self.in_flight = Some((id, line.to_owned(), pos));
        }

        if let Some(prev) = &self.last_ready {
            CompletionResult::stale_or_pending(
                Arc::clone(&prev.suggestions),
                CompletionOrigin::new(prev.line.clone(), prev.pos),
            )
        } else {
            CompletionResult::Pending
        }
    }

    fn poll_completion(&mut self) -> CompletionStatus {
        if self.drain_responses() {
            return CompletionStatus::Ready;
        }
        if self.in_flight.is_some() {
            CompletionStatus::Pending
        } else {
            CompletionStatus::Idle
        }
    }
}

/// Nushell AST syntax highlighter for `reedline`.
pub struct NuSyntaxHighlighter {
    engine_state: EngineState,
}

impl NuSyntaxHighlighter {
    #[must_use]
    pub fn new(engine_state: EngineState) -> Self {
        Self { engine_state }
    }
}

impl Highlighter for NuSyntaxHighlighter {
    fn highlight(&self, line: &str, _cursor: usize) -> StyledText {
        let mut styled = StyledText::new();
        if line.is_empty() {
            return styled;
        }

        let mut working_set = StateWorkingSet::new(&self.engine_state);
        let offset = working_set.next_span_start();
        let block = nu_parser::parse(&mut working_set, None, line.as_bytes(), false);
        let shapes = flatten_block(&working_set, &block);

        let mut last_idx = 0_usize;
        for (span, shape) in shapes {
            let start = span.start.saturating_sub(offset).min(line.len());
            let end = span.end.saturating_sub(offset).min(line.len());
            if start < last_idx || end <= start {
                continue;
            }
            if start > last_idx {
                styled.push((Style::new(), line[last_idx..start].to_owned()));
            }
            let style = style_for_shape(&shape);
            styled.push((style, line[start..end].to_owned()));
            last_idx = end;
        }
        if last_idx < line.len() {
            styled.push((Style::new(), line[last_idx..].to_owned()));
        }
        styled
    }
}

fn style_for_shape(shape: &FlatShape) -> Style {
    match shape {
        FlatShape::InternalCall(_) | FlatShape::Keyword => Style::new().fg(Color::Cyan).bold(),
        FlatShape::External(_) | FlatShape::ExternalResolved => {
            Style::new().fg(Color::LightCyan).bold()
        }
        FlatShape::Flag => Style::new().fg(Color::Yellow),
        FlatShape::Pipe | FlatShape::Redirection => Style::new().fg(Color::Purple).bold(),
        FlatShape::String | FlatShape::RawString | FlatShape::StringInterpolation => {
            Style::new().fg(Color::Green)
        }
        FlatShape::Int | FlatShape::Float | FlatShape::DateTime => {
            Style::new().fg(Color::LightMagenta)
        }
        FlatShape::Variable(_) | FlatShape::VarDecl(_) => Style::new().fg(Color::Magenta),
        FlatShape::Filepath | FlatShape::Directory | FlatShape::GlobPattern => {
            Style::new().fg(Color::Blue)
        }
        FlatShape::Garbage => Style::new().fg(Color::Red).bold(),
        _ => Style::new(),
    }
}

/// Multiline Nushell input validator for `reedline`.
pub struct NuValidator {
    engine_state: EngineState,
}

impl NuValidator {
    #[must_use]
    pub fn new(engine_state: EngineState) -> Self {
        Self { engine_state }
    }
}

impl Validator for NuValidator {
    fn validate(&self, line: &str) -> ValidationResult {
        let mut working_set = StateWorkingSet::new(&self.engine_state);
        let _ = nu_parser::parse(&mut working_set, None, line.as_bytes(), false);
        let is_incomplete = working_set.parse_errors.iter().any(|err| {
            matches!(
                err,
                nu_protocol::ParseError::UnexpectedEof(_, _)
                    | nu_protocol::ParseError::Unclosed(..)
            )
        });
        if is_incomplete {
            ValidationResult::Incomplete
        } else {
            ValidationResult::Complete
        }
    }
}
