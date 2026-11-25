//! Async-first userland SDK for Helios wasm programs.
//!
//! Each capability area lives behind a Cargo feature so programs only
//! link the WIT interfaces they use: `btrfs`, `fs`, `http`, `http-handler`, `http-kit-io`,
//! `hv`, `inspect`, `inspect-publish`, `io`, `ipc`, `machine-identity`, `mounts`, `net`,
//! `programs`, `serial`, `settings`, `snapshot`, `sync`, `task`, `tracing`, `profiling`,
//! `instances`, `display`, `gpu`, `input`, `surface`,
//! `compositor`, `audio`, `vsock`, and `channel`. `bindings` exposes the raw generated WIT
//! bindings for anything the typed helpers do not cover, and
//! [`main`](macro@main) wraps a program's async entry point.

#[cfg(feature = "audio")]
pub mod audio;
pub mod bindings;
#[cfg(feature = "btrfs")]
pub mod btrfs;
#[cfg(feature = "channel")]
pub mod channel;
#[cfg(feature = "compositor")]
pub mod compositor;
#[cfg(feature = "display")]
pub mod display;
#[cfg(any(feature = "fs", feature = "io"))]
mod error;
#[cfg(feature = "fs")]
pub mod fs;
#[cfg(any(feature = "display", feature = "gpu", feature = "surface"))]
pub mod image;

#[cfg(feature = "gpu")]
pub mod gpu;
#[cfg(any(feature = "http", feature = "http-handler"))]
pub mod http;
#[cfg(feature = "http-kit-io")]
pub mod http_kit;
#[cfg(feature = "hv")]
pub mod hv;
#[cfg(feature = "input")]
pub mod input;
#[cfg(feature = "inspect")]
pub mod inspect;
#[cfg(feature = "instances")]
pub mod instances;
#[cfg(feature = "io")]
pub mod io;
#[cfg(feature = "ipc")]
pub mod ipc;
#[cfg(feature = "programs")]
pub mod linux;
#[cfg(feature = "machine-identity")]
pub mod machine_identity;
#[cfg(any(
    feature = "display",
    feature = "gpu",
    feature = "inspect-publish",
    feature = "surface"
))]
pub mod memory;
#[cfg(feature = "mounts")]
pub mod mounts;
#[cfg(feature = "net")]
pub mod net;
#[cfg(feature = "oci")]
pub mod oci;
pub mod prelude;
#[cfg(feature = "processors")]
pub mod processors;
#[cfg(feature = "profiling")]
pub mod profiling;
#[cfg(feature = "programs")]
pub mod programs;
#[cfg(feature = "serial")]
pub mod serial;
#[cfg(feature = "settings")]
pub mod settings;
#[cfg(feature = "snapshot")]
pub mod snapshot;
#[cfg(feature = "surface")]
pub mod surface;
#[cfg(feature = "sync")]
pub mod sync;
#[cfg(feature = "task")]
pub mod task;
#[cfg(feature = "tracing")]
pub mod tracing;
#[cfg(feature = "vsock")]
pub mod vsock;
#[cfg(feature = "webgpu")]
pub mod webgpu;

#[cfg(any(feature = "fs", feature = "io"))]
pub use error::Result;
#[cfg(feature = "io")]
pub use futures_io::{AsyncRead, AsyncWrite};
pub use helios_api_macro::main;
#[cfg(feature = "io")]
pub use io::{ReadExt, WriteExt};
#[cfg(feature = "io")]
pub use std::io::Error;
use std::io::Write as _;
pub use wit_bindgen;
#[cfg(all(feature = "http", not(feature = "http-handler")))]
pub use zenwave;

/// Whether a component-model stream read result means the stream is closed.
///
/// `StreamReader::read` reports the outcome of one read; every caller that
/// drains a stream needs the same test for "nothing more is coming", so it
/// lives here rather than in each of them.
pub fn stream_closed(result: wit_bindgen::rt::async_support::StreamResult) -> bool {
    use wit_bindgen::rt::async_support::StreamResult;
    matches!(
        result,
        StreamResult::Dropped | StreamResult::Cancelled | StreamResult::Complete(0)
    )
}

/// Return values accepted from a `#[helios_api::main]` entry point.
///
/// `()` always succeeds; `Result<(), E>` prints the error to stderr and
/// exits with failure. Implemented here rather than via `Termination`
/// because the wasm component entry point reports success as a plain
/// `Result<(), ()>` to the host.
#[allow(clippy::result_unit_err)]
pub trait MainOutput {
    fn into_run_result(self) -> core::result::Result<(), ()>;
}

impl MainOutput for () {
    fn into_run_result(self) -> core::result::Result<(), ()> {
        Ok(())
    }
}

impl<E> MainOutput for core::result::Result<(), E>
where
    E: core::fmt::Display,
{
    fn into_run_result(self) -> core::result::Result<(), ()> {
        match self {
            Ok(()) => Ok(()),
            Err(error) => {
                let _ = writeln!(std::io::stderr().lock(), "{error}");
                Err(())
            }
        }
    }
}
