//! The WebGPU provider: `wasi:webgpu` and the platform canvas as a component.
//!
//! It is composed into the store of the program that imports them, so every
//! program owns its own Venus connection and GPU memory accounting. The
//! implementation lives in `helios-webgpu`; this crate only binds it to the
//! component world.

use helios_webgpu::component::provider::Provider;

// The export macro names the generated bindings through this module path.
mod bindings {
    pub use ::helios_api::bindings::*;
}

::helios_api::bindings::export!(Provider);
