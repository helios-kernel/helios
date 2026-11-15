//! WebGPU errors are scoped to the device, not a native thread's error stack.

use async_channel::{Receiver, Sender};
use core::cell::RefCell;

use crate::runtime::{Device, GpuError, GpuErrorKind};

struct Scope {
    filter: GpuErrorKind,
    first: Option<GpuError>,
}

pub struct ErrorSink {
    scopes: RefCell<Vec<Scope>>,
    send: Sender<GpuError>,
    events: Receiver<GpuError>,
}

impl Default for ErrorSink {
    fn default() -> Self {
        let (send, events) = async_channel::unbounded();
        Self {
            scopes: RefCell::new(Vec::new()),
            send,
            events,
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
            // A dropped stream no longer observes uncaptured errors.
            let _ = self.send.try_send(error);
        }
    }

    pub fn events(&self) -> Receiver<GpuError> {
        self.events.clone()
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

    pub fn drain(&self) {
        while let Ok(error) = self.device.errors().try_recv() {
            self.errors.report(error);
        }
    }

    pub fn native<T>(&self, call: impl FnOnce() -> T) -> T {
        let value = call();
        self.drain();
        value
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
        errors.push(GpuErrorKind::Validation);
        errors.push(GpuErrorKind::OutOfMemory);
        errors.report(error(GpuErrorKind::Validation, "first validation"));
        errors.report(error(GpuErrorKind::Validation, "second validation"));
        errors.report(error(GpuErrorKind::Internal, "uncaptured"));
        assert!(errors.pop().unwrap().is_none());
        assert_eq!(errors.pop().unwrap().unwrap().message, "first validation");
        assert_eq!(errors.events().try_recv().unwrap().message, "uncaptured");
        assert!(errors.pop().is_err());
    }

    #[test]
    fn a_full_inner_scope_does_not_spill_into_an_outer_scope() {
        let errors = ErrorSink::default();
        errors.push(GpuErrorKind::Validation);
        errors.push(GpuErrorKind::Validation);
        errors.report(error(GpuErrorKind::Validation, "first"));
        errors.report(error(GpuErrorKind::Validation, "second"));
        assert_eq!(errors.pop().unwrap().unwrap().message, "first");
        assert!(errors.pop().unwrap().is_none());
        assert!(errors.events().try_recv().is_err());
    }
}
