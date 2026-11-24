//! Async-first host Nushell REPL, script runner, and live `<Tab>` completion
//! built on `helios-nu`, `helios-ops`, and `reedline 0.53.0`.
//!
//! Zero `block_on` and zero `anyhow` appear in production paths.

pub mod cache;
pub mod completer;
pub mod env;
pub mod error;
pub mod repl;

pub use cache::{COMPLETION_CACHE_TTL, COMPLETION_REMOTE_TIMEOUT, RemoteCompletionCache};
pub use completer::{
    AsyncReedlineCompleter, NuSyntaxHighlighter, NuValidator, spawn_completion_worker,
};
pub use env::HostEnv;
pub use error::ReplError;
pub use repl::{OutputFormat, eval_command, eval_script, format_value, run_repl};
