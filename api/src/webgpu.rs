//! WebGPU for a program: `wasi:webgpu` and the platform canvas it draws
//! into.
//!
//! A program that enables this feature imports both interfaces, and its
//! build plugs the WebGPU provider into them, so the GPU device, its memory
//! and the canvas's window all belong to the program's own instance.
//! Configure the canvas's `context()` with a device, draw into
//! `get-current-texture`, and `present` hands the frame to the compositor.

pub use crate::bindings::helios::webgpu::canvas::{Canvas, Error as CanvasError};
pub use crate::bindings::wasi::webgpu::webgpu::*;
