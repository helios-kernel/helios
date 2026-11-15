//! User-space WebGPU over an instance-owned Venus connection.

#[cfg(feature = "runtime")]
pub mod runtime;

#[cfg(feature = "runtime")]
pub use wgpu;

#[cfg(feature = "component")]
pub mod component;
