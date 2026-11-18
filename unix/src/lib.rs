#![no_std]

//! Optional UNIX compatibility services shared by native and WebAssembly ABIs.
//! Tables are single-owner unless their type documents synchronization.
//! Notifications and execution interrupts are supplied by the platform; this
//! crate has no dependency on the kernel, Wasmtime, WASIX or Linux ABI.
extern crate alloc;

mod termination;
pub use termination::{ChildTermination, SignalTermination};

#[cfg(feature = "runtime")]
mod runtime;
#[cfg(feature = "runtime")]
pub use runtime::*;
