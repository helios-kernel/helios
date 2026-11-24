//! Typed error definitions for `helios-inspector-shell`.

use std::io;
use std::path::PathBuf;

use helios_nu::NuError;
use helios_ops::OpsError;

/// Errors returned by the host Nushell REPL and script runner.
#[derive(Debug, thiserror::Error)]
pub enum ReplError {
    #[error("{0}")]
    Nu(#[from] NuError),
    #[error("{0}")]
    Ops(#[from] OpsError),
    #[error("failed to read script file {path}: {source}")]
    ReadScript {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to initialize line editor history at {path}: {source}")]
    History {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("terminal I/O error: {source}")]
    Terminal {
        #[source]
        source: io::Error,
    },
    #[error("background line-editor task failed: {detail}")]
    EditorTask { detail: String },
    #[error("failed to encode output as JSON: {source}")]
    EncodeJson {
        #[source]
        source: serde_json::Error,
    },
}
