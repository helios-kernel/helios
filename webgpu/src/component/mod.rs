//! Resource implementations of wasi:webgpu.
//!
//! The provider runs WebGPU's two timelines. The content timeline is every
//! export: a synchronous one allocates ids and content-side state, queues a
//! [`command::Command`] and returns, so none waits on the host, as WASI
//! 0.3 requires of a function that is not `async`. The device timeline is
//! one task per device ([`timeline`]) that owns wgpu-core and executes the
//! queue in order; async exports queue their command and await its answer.

pub use helios_api::bindings::exports::wasi::webgpu::webgpu as wit;

pub mod value;

pub mod convert;

pub mod ids;

pub mod scope;

pub mod command;

pub mod content;

pub mod instance;

pub mod timeline;

pub mod resource;

pub mod buffer;

pub mod queue;

pub mod recording;

pub mod render;

pub mod encoder;

pub mod device;

pub mod pipeline;

pub mod capability;

pub mod adapter;

pub mod gpu;

pub mod presentation;

pub mod canvas;

pub mod provider;
