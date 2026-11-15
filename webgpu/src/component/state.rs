//! WebGPU errors are scoped to the device, not a native thread's error stack.

use async_channel::{Receiver, Sender};
use core::cell::RefCell;

use super::backend::Device;
use crate::runtime::{GpuError, GpuErrorKind};
use wgpu_types::error::{ErrorType, WebGpuError};

struct Scope {
    filter: GpuErrorKind,
    first: Option<GpuError>,
}

pub struct ErrorSink {
    scopes: RefCell<Vec<Scope>>,
    subscribers: RefCell<Vec<Sender<GpuError>>>,
}

impl Default for ErrorSink {
    fn default() -> Self {
        Self {
            scopes: RefCell::new(Vec::new()),
            subscribers: RefCell::new(Vec::new()),
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("pop-error-scope has no matching push-error-scope")]
pub struct MissingScope;

impl ErrorSink {
    pub fn push(&self, filter: GpuErrorKind) {
        self.scopes.borrow_mut().push(Scope {
            filter,
            first: None,
        });
    }

    pub fn pop(&self) -> Result<Option<GpuError>, MissingScope> {
        self.scopes
            .borrow_mut()
            .pop()
            .map(|scope| scope.first)
            .ok_or(MissingScope)
    }

    pub fn report(&self, error: GpuError) {
        if let Some(scope) = self
            .scopes
            .borrow_mut()
            .iter_mut()
            .rev()
            .find(|scope| scope.filter == error.kind)
        {
            if scope.first.is_none() {
                scope.first = Some(error);
            }
        } else {
            // Each WIT stream observes the event independently. Closed readers
            // are removed, and no subscriber means there is no event backlog.
            self.subscribers
                .borrow_mut()
                .retain(|send| send.try_send(error.clone()).is_ok());
        }
    }

    pub fn events(&self) -> Receiver<GpuError> {
        let (send, events) = async_channel::unbounded();
        self.subscribers.borrow_mut().push(send);
        events
    }
}

pub struct DeviceState {
    pub device: Device,
    pub errors: ErrorSink,
}

impl DeviceState {
    pub fn new(device: Device) -> Self {
        Self {
            device,
            errors: ErrorSink::default(),
        }
    }

    pub fn report(&self, error: &impl WebGpuError) {
        let kind = match error.webgpu_error_type() {
            ErrorType::Validation => GpuErrorKind::Validation,
            ErrorType::OutOfMemory => GpuErrorKind::OutOfMemory,
            ErrorType::Internal => GpuErrorKind::Internal,
            ErrorType::DeviceLost => return,
        };
        let mut causes = Vec::new();
        let mut source = error.source();
        while let Some(cause) = source {
            causes.push(cause.to_string());
            source = cause.source();
        }
        self.errors.report(GpuError {
            kind,
            message: error.to_string(),
            causes,
        });
    }

    pub fn created<T, E: WebGpuError>(&self, (value, error): (T, Option<E>)) -> T {
        if let Some(error) = error {
            self.report(&error);
        }
        value
    }

    pub fn native<T, E: WebGpuError>(&self, call: impl FnOnce() -> Result<T, E>) -> Option<T> {
        match call() {
            Ok(value) => Some(value),
            Err(error) => {
                self.report(&error);
                None
            }
        }
    }

    pub fn invalid(&self, message: impl Into<String>) {
        self.errors.report(GpuError {
            kind: GpuErrorKind::Validation,
            message: message.into(),
            causes: Vec::new(),
        });
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
        let errors = ErrorSink::default();
        let events = errors.events();
        errors.push(GpuErrorKind::Validation);
        errors.push(GpuErrorKind::OutOfMemory);
        errors.report(error(GpuErrorKind::Validation, "first validation"));
        errors.report(error(GpuErrorKind::Validation, "second validation"));
        errors.report(error(GpuErrorKind::Internal, "uncaptured"));
        assert!(errors.pop().unwrap().is_none());
        assert_eq!(errors.pop().unwrap().unwrap().message, "first validation");
        assert_eq!(events.try_recv().unwrap().message, "uncaptured");
        assert!(errors.pop().is_err());
    }

    #[test]
    fn a_full_inner_scope_does_not_spill_into_an_outer_scope() {
        let errors = ErrorSink::default();
        let events = errors.events();
        errors.push(GpuErrorKind::Validation);
        errors.push(GpuErrorKind::Validation);
        errors.report(error(GpuErrorKind::Validation, "first"));
        errors.report(error(GpuErrorKind::Validation, "second"));
        assert_eq!(errors.pop().unwrap().unwrap().message, "first");
        assert!(errors.pop().unwrap().is_none());
        assert!(events.try_recv().is_err());
    }

    #[test]
    fn uncaptured_events_broadcast_and_close_with_the_device_sink() {
        let errors = ErrorSink::default();
        errors.report(error(GpuErrorKind::Internal, "before subscription"));
        let first = errors.events();
        let second = errors.events();
        assert!(first.try_recv().is_err());
        errors.report(error(GpuErrorKind::Validation, "both"));
        assert_eq!(first.try_recv().unwrap().message, "both");
        assert_eq!(second.try_recv().unwrap().message, "both");
        drop(first);
        errors.report(error(GpuErrorKind::Internal, "remaining"));
        assert_eq!(second.try_recv().unwrap().message, "remaining");
        assert_eq!(errors.subscribers.borrow().len(), 1);
        drop(errors);
        assert!(second.is_closed());
    }
}
