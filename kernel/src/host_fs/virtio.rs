//! The virtio-9p device as a [`HostFsTransport`].
//!
//! Every backend that carries the host share on virtio-9p names its device
//! type and nothing else: the buffer sizing, the reply length check and the
//! interrupt forwarding are the same whatever bus the device sits on.
//!
//! Concurrency contract: the device pipelines requests and routes each
//! completion back to the task that submitted it, so every clone of the
//! transport submits straight to it without a lock of its own. The device is
//! constructed before interrupts are enabled; afterwards
//! [`ExternalInterruptHandler::handle_interrupt`] only acknowledges the
//! device and wakes the waiters, from any processor.

use helios_hal::dma::BufResult;
use helios_hal::io::IoError;
use helios_virtio::{TransportBuffer, Virtio9pDevice, VirtioTransport};
use triomphe::Arc;

use crate::{ExternalInterruptHandler, HostFsTransport};

/// A [`Virtio9pDevice`] shared by the host file system client and the
/// interrupt route that wakes it.
pub struct Virtio9pTransport<T: VirtioTransport> {
    device: Arc<Virtio9pDevice<T>>,
}

impl<T: VirtioTransport> Virtio9pTransport<T> {
    /// Takes ownership of a device that finished its initialization.
    pub fn new(device: Virtio9pDevice<T>) -> Self {
        Self {
            device: Arc::new(device),
        }
    }
}

// Not derived: a derive would require `T: Clone`, and the device is shared.
impl<T: VirtioTransport> Clone for Virtio9pTransport<T> {
    fn clone(&self) -> Self {
        Self {
            device: Arc::clone(&self.device),
        }
    }
}

impl<T: VirtioTransport> ExternalInterruptHandler for Virtio9pTransport<T> {
    fn handle_interrupt(&self) {
        self.device.handle_interrupt();
    }
}

impl<T: VirtioTransport> HostFsTransport for Virtio9pTransport<T> {
    fn mount_tag(&self) -> &str {
        self.device.mount_tag()
    }

    fn pipeline_depth(&self) -> usize {
        self.device.pipeline_depth()
    }

    type Buffer = TransportBuffer<T>;

    fn buffer(&self, capacity: usize) -> Result<Self::Buffer, IoError> {
        self.device.buffer(capacity)
    }

    async fn request(
        &self,
        request: Self::Buffer,
        request_len: usize,
        response: Self::Buffer,
        response_len: usize,
    ) -> BufResult<usize, (Self::Buffer, Self::Buffer)> {
        self.device
            .request(request, request_len, response, response_len)
            .await
    }
}
