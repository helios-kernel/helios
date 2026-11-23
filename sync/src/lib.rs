#![no_std]
//! Executor-independent async synchronization shared by kernel mechanisms and
//! optional compatibility services. Every primitive states its SMP contract.
#[cfg(feature = "runtime")]
mod runtime;
#[cfg(feature = "runtime")]
pub use runtime::*;

extern crate alloc;
#[cfg(test)]
extern crate std;

#[cfg(feature = "runtime")]
mod byte_channel;
#[cfg(feature = "runtime")]
pub use byte_channel::*;
