//! Typed error definitions for `helios-nu`.

use nu_protocol::shell_error::generic::GenericError;
use nu_protocol::{CompileError, ParseError, ShellError, Span};
use thiserror::Error;

/// Top-level error returned by [`crate::ShellSession`] and [`crate::eval_source_async`].
#[derive(Debug, Error)]
pub enum NuError {
    /// Source failed to parse into a Nushell AST.
    #[error("parse error: {message}")]
    Parse {
        message: String,
        errors: Vec<ParseError>,
    },
    /// Compiled AST failed IR compilation.
    #[error("compile error: {0}")]
    Compile(#[source] Box<CompileError>),
    /// Runtime evaluation error.
    #[error("evaluation error: {0}")]
    Eval(#[from] Box<ShellError>),
    /// Environment / capability backend failure.
    #[error("environment error: {0}")]
    Env(#[from] EnvError),
}

impl From<ShellError> for NuError {
    fn from(error: ShellError) -> Self {
        Self::Eval(Box::new(error))
    }
}

/// Typed failure reported by a [`crate::HeliosEnv`] implementation.
#[derive(Debug, Clone, Error)]
pub enum EnvError {
    #[error("not found: {path}")]
    NotFound { path: String },
    #[error("permission denied: {detail}")]
    PermissionDenied { detail: String },
    #[error("already exists: {path}")]
    AlreadyExists { path: String },
    #[error("not a directory: {path}")]
    NotADirectory { path: String },
    #[error("is a directory: {path}")]
    IsADirectory { path: String },
    #[error("invalid argument: {detail}")]
    InvalidArgument { detail: String },
    #[error("operation unsupported: {detail}")]
    Unsupported { detail: String },
    #[error("i/o error: {detail}")]
    Io { detail: String },
    #[error("process error: {detail}")]
    Process { detail: String },
    #[error("http error: {detail}")]
    Http { detail: String },
}

impl EnvError {
    /// Convert an environment error into a Nushell [`ShellError`] attributed to `span`.
    #[must_use]
    pub fn into_shell_error(self, title: &str, span: Span) -> ShellError {
        let detail = self.to_string();
        ShellError::Generic(GenericError::new(
            format!("{title}: {detail}"),
            detail,
            span,
        ))
    }
}

/// Build a concise [`ShellError::Generic`] attributed to `span`.
#[must_use]
pub fn generic_error(title: impl Into<String>, msg: impl Into<String>, span: Span) -> ShellError {
    let title = title.into();
    let msg = msg.into();
    let headline = if msg.is_empty() || title == msg {
        title
    } else {
        format!("{title}: {msg}")
    };
    ShellError::Generic(GenericError::new(headline, msg, span))
}
