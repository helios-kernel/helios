//! Owned GPU images shared by rendering, surfaces, and display scanout.

use crate::bindings::helios::system::gpu as raw;

pub use raw::{ImageLayout, PixelFormat};

/// Validated image storage retained independently of its originating blob.
pub struct Image {
    raw: raw::Image,
}

impl From<raw::Image> for Image {
    fn from(raw: raw::Image) -> Self {
        Self { raw }
    }
}

impl Image {
    pub fn layout(&self) -> ImageLayout {
        raw::describe_image(&self.raw)
    }

    pub fn handle(&self) -> &raw::Image {
        &self.raw
    }
}
