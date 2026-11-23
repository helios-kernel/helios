//! Immutable image capabilities. Cloning retains the blob atomically; dropping
//! the last capability wakes device cleanup. Layout validation happens before
//! taking a hold, and consumers cannot change the layout independently of it.

use helios_hal::display::{BlobScanout, DisplayMode, PixelFormat};
use triomphe::Arc;

use super::service::BlobShared;
use super::{BlobHold, Gpu3dServiceError};

#[derive(Clone)]
pub struct GpuImage {
    layout: BlobScanout,
    hold: BlobHold,
}

impl GpuImage {
    pub(crate) fn new(
        blob: &Arc<BlobShared>,
        mode: DisplayMode,
        format: PixelFormat,
        offset: u32,
        stride: u32,
    ) -> Result<Self, Gpu3dServiceError> {
        let layout = BlobScanout {
            blob: blob.id(),
            mode,
            format,
            offset,
            stride,
        };
        if !layout.fits_in(blob.size()) {
            return Err(Gpu3dServiceError::InvalidBlob);
        }
        Ok(Self {
            layout,
            hold: BlobHold::new(blob),
        })
    }

    pub const fn layout(&self) -> BlobScanout {
        self.layout
    }

    /// Transfer the capability into a scanout without releasing its retention.
    pub fn into_scanout(self) -> (BlobScanout, BlobHold) {
        (self.layout, self.hold)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::Notify;
    use helios_hal::display::{BlobId, BlobMemory, BlobUsage};

    fn test_blob(size: u64) -> Arc<BlobShared> {
        Arc::new(BlobShared::new(
            BlobId::new(1),
            size,
            BlobMemory::Host3d,
            BlobUsage::SHAREABLE,
            Arc::new(Notify::new()),
        ))
    }

    #[test]
    fn image_clones_keep_the_blob_until_the_last_consumer_releases_it() {
        let blob = test_blob(128);
        let image = GpuImage::new(
            &blob,
            DisplayMode {
                width: 4,
                height: 4,
            },
            PixelFormat::Rgba8888,
            0,
            32,
        )
        .unwrap();
        let other = image.clone();
        drop(image);
        assert!(blob.is_retained());
        let (layout, scanout) = other.into_scanout();
        assert_eq!(layout.blob, blob.id());
        assert_eq!(layout.stride, 32);
        assert!(blob.is_retained());
        drop(scanout);
        assert!(!blob.is_retained());
    }

    #[test]
    fn invalid_layouts_take_no_hold() {
        let blob = test_blob(128);
        for (width, height, offset, stride) in [(0, 4, 0, 32), (4, 4, 0, 15), (4, 4, 1, 32)] {
            assert!(matches!(
                GpuImage::new(
                    &blob,
                    DisplayMode { width, height },
                    PixelFormat::Rgba8888,
                    offset,
                    stride,
                ),
                Err(Gpu3dServiceError::InvalidBlob)
            ));
            assert!(!blob.is_retained());
        }
    }
}
