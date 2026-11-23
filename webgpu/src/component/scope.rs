//! WebGPU error scopes across the two timelines.
//!
//! `push-error-scope` and `pop-error-scope` act on the content timeline.
//! Every queued command carries a snapshot of the scope stack as it stood
//! when the command was queued, so an error the device timeline produces
//! later lands in the scope that was innermost at the call, even when the
//! application has pushed or popped scopes since. Errors no scope accepts
//! go to the device's uncaptured-error subscribers.

use core::cell::RefCell;
use std::rc::Rc;

use async_channel::Sender;
use wgpu_types::error::{ErrorType, WebGpuError};

use crate::runtime::{GpuError, GpuErrorKind};

/// One pushed scope. Its first matching error is final once the device
/// timeline has passed every command queued while it was open.
pub struct Scope {
    filter: GpuErrorKind,
    first: RefCell<Option<GpuError>>,
}

impl Scope {
    pub fn take(&self) -> Option<GpuError> {
        self.first.borrow_mut().take()
    }
}

/// One link of the scope stack; opaque outside this module.
pub struct Node {
    scope: Rc<Scope>,
    parent: Option<Rc<Node>>,
}

/// Where the errors of one queued command go.
#[derive(Clone)]
pub enum ErrorTarget {
    /// The scope stack at the call: innermost matching scope, else uncaptured.
    Scopes(Option<Rc<Node>>),
    /// The command produces an invalid object whose error the content
    /// timeline has already reported, so core's own report is dropped.
    Discard,
}

impl ErrorTarget {
    /// Deliver `error` to its scope, or hand it back when no scope takes it.
    fn capture(&self, error: GpuError) -> Option<GpuError> {
        let mut node = match self {
            Self::Scopes(node) => node.as_deref(),
            Self::Discard => return None,
        };
        while let Some(current) = node {
            if current.scope.filter == error.kind {
                let mut first = current.scope.first.borrow_mut();
                if first.is_none() {
                    *first = Some(error);
                }
                return None;
            }
            node = current.parent.as_deref();
        }
        Some(error)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("pop-error-scope has no matching push-error-scope")]
pub struct MissingScope;

/// The content timeline's scope stack. Each push links a node onto the
/// previous top, so a snapshot is one reference count.
pub struct ScopeStack {
    top: RefCell<Option<Rc<Node>>>,
}

impl Default for ScopeStack {
    fn default() -> Self {
        Self {
            top: RefCell::new(None),
        }
    }
}

impl ScopeStack {
    pub fn push(&self, filter: GpuErrorKind) {
        let mut top = self.top.borrow_mut();
        let parent = top.take();
        *top = Some(Rc::new(Node {
            scope: Rc::new(Scope {
                filter,
                first: RefCell::new(None),
            }),
            parent,
        }));
    }

    pub fn pop(&self) -> Result<Rc<Scope>, MissingScope> {
        let mut top = self.top.borrow_mut();
        let node = top.take().ok_or(MissingScope)?;
        *top = node.parent.clone();
        Ok(node.scope.clone())
    }

    pub fn current(&self) -> ErrorTarget {
        ErrorTarget::Scopes(self.top.borrow().clone())
    }
}

/// The device timeline's end of error reporting.
#[derive(Default)]
pub struct ErrorSink {
    subscribers: Vec<Sender<GpuError>>,
}

impl ErrorSink {
    pub fn report(&mut self, target: &ErrorTarget, error: GpuError) {
        if let Some(error) = target.capture(error) {
            // Each WIT stream observes the event independently. Closed
            // readers are removed, and no subscriber means no backlog.
            self.subscribers
                .retain(|send| send.try_send(error.clone()).is_ok());
        }
    }

    pub fn subscribe(&mut self, events: Sender<GpuError>) {
        self.subscribers.push(events);
    }

    /// Report a wgpu-core error; device loss is reported through `lost`.
    pub fn native(&mut self, target: &ErrorTarget, error: &impl WebGpuError) {
        if let Some(error) = gpu_error(error) {
            self.report(target, error);
        }
    }
}

/// The WebGPU class and diagnostic chain of a wgpu-core error, or `None`
/// for device loss.
pub fn gpu_error(error: &impl WebGpuError) -> Option<GpuError> {
    let kind = match error.webgpu_error_type() {
        ErrorType::Validation => GpuErrorKind::Validation,
        ErrorType::OutOfMemory => GpuErrorKind::OutOfMemory,
        ErrorType::Internal => GpuErrorKind::Internal,
        ErrorType::DeviceLost => return None,
    };
    let mut causes = Vec::new();
    let mut source = error.source();
    while let Some(cause) = source {
        causes.push(cause.to_string());
        source = cause.source();
    }
    Some(GpuError {
        kind,
        message: error.to_string(),
        causes,
    })
}

pub fn validation(message: impl Into<String>) -> GpuError {
    GpuError {
        kind: GpuErrorKind::Validation,
        message: message.into(),
        causes: Vec::new(),
    }
}

pub fn internal(message: impl Into<String>) -> GpuError {
    GpuError {
        kind: GpuErrorKind::Internal,
        message: message.into(),
        causes: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn error(kind: GpuErrorKind, message: &str) -> GpuError {
        GpuError {
            kind,
            message: message.into(),
            causes: Vec::new(),
        }
    }

    #[test]
    fn innermost_matching_scope_captures_only_the_first_error() {
        let stack = ScopeStack::default();
        let mut sink = ErrorSink::default();
        let (events, uncaptured) = async_channel::unbounded();
        sink.subscribe(events);
        stack.push(GpuErrorKind::Validation);
        stack.push(GpuErrorKind::OutOfMemory);
        let target = stack.current();
        sink.report(&target, error(GpuErrorKind::Validation, "first validation"));
        sink.report(
            &target,
            error(GpuErrorKind::Validation, "second validation"),
        );
        sink.report(&target, error(GpuErrorKind::Internal, "uncaptured"));
        assert!(stack.pop().unwrap().take().is_none());
        assert_eq!(
            stack.pop().unwrap().take().unwrap().message,
            "first validation"
        );
        assert_eq!(uncaptured.try_recv().unwrap().message, "uncaptured");
        assert!(stack.pop().is_err());
    }

    #[test]
    fn a_full_inner_scope_does_not_spill_into_an_outer_scope() {
        let stack = ScopeStack::default();
        let mut sink = ErrorSink::default();
        let (events, uncaptured) = async_channel::unbounded();
        sink.subscribe(events);
        stack.push(GpuErrorKind::Validation);
        stack.push(GpuErrorKind::Validation);
        let target = stack.current();
        sink.report(&target, error(GpuErrorKind::Validation, "first"));
        sink.report(&target, error(GpuErrorKind::Validation, "second"));
        assert_eq!(stack.pop().unwrap().take().unwrap().message, "first");
        assert!(stack.pop().unwrap().take().is_none());
        assert!(uncaptured.try_recv().is_err());
    }

    #[test]
    fn a_command_reports_to_the_scopes_open_when_it_was_queued() {
        let stack = ScopeStack::default();
        let mut sink = ErrorSink::default();
        let (events, uncaptured) = async_channel::unbounded();
        sink.subscribe(events);
        stack.push(GpuErrorKind::Validation);
        let queued_inside = stack.current();
        let scope = stack.pop().unwrap();
        let queued_after = stack.current();
        stack.push(GpuErrorKind::Validation);
        // The device timeline reaches both commands only now.
        sink.report(&queued_inside, error(GpuErrorKind::Validation, "inside"));
        sink.report(&queued_after, error(GpuErrorKind::Validation, "after"));
        assert_eq!(scope.take().unwrap().message, "inside");
        assert!(stack.pop().unwrap().take().is_none());
        assert_eq!(uncaptured.try_recv().unwrap().message, "after");
    }

    #[test]
    fn discarded_errors_reach_neither_scopes_nor_subscribers() {
        let stack = ScopeStack::default();
        let mut sink = ErrorSink::default();
        let (events, uncaptured) = async_channel::unbounded();
        sink.subscribe(events);
        stack.push(GpuErrorKind::Validation);
        sink.report(
            &ErrorTarget::Discard,
            error(GpuErrorKind::Validation, "stand-in"),
        );
        assert!(stack.pop().unwrap().take().is_none());
        assert!(uncaptured.try_recv().is_err());
    }

    #[test]
    fn uncaptured_events_broadcast_and_drop_closed_subscribers() {
        let mut sink = ErrorSink::default();
        let target = ScopeStack::default().current();
        sink.report(
            &target,
            error(GpuErrorKind::Internal, "before subscription"),
        );
        let (first_events, first) = async_channel::unbounded();
        let (second_events, second) = async_channel::unbounded();
        sink.subscribe(first_events);
        sink.subscribe(second_events);
        assert!(first.try_recv().is_err());
        sink.report(&target, error(GpuErrorKind::Validation, "both"));
        assert_eq!(first.try_recv().unwrap().message, "both");
        assert_eq!(second.try_recv().unwrap().message, "both");
        drop(first);
        sink.report(&target, error(GpuErrorKind::Internal, "remaining"));
        assert_eq!(second.try_recv().unwrap().message, "remaining");
        assert_eq!(sink.subscribers.len(), 1);
        drop(sink);
        assert!(second.is_closed());
    }
}
