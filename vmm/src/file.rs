//! Async file and block-storage abstractions over WASI 0.3 descriptors.

use core::future::Future;

use futures_lite::future::zip;
use helios_api::{
    bindings::wasi::filesystem::{
        preopens,
        types::{Descriptor, DescriptorFlags, OpenFlags, PathFlags},
    },
    hv::{GuestPhysAddr, GuestRegion, MemoryBackend, TRANSFER_CHUNK_BYTES},
};

use crate::error::{Error, Result};

/// Zero-`dyn` async block-device backing store.
pub trait BlockBackend {
    fn size(&self) -> u64;
    fn read(&self, offset: u64, length: usize) -> impl Future<Output = Result<Vec<u8>>> + '_;
    fn write(&self, offset: u64, bytes: Vec<u8>) -> impl Future<Output = Result<()>> + '_;
}

/// Async file handle backed by a WASI 0.3 [`Descriptor`].
pub struct WasiFile {
    descriptor: Descriptor,
    size: u64,
}

impl WasiFile {
    /// Opens `path` relative to the `/` WASI preopen directory.
    pub async fn open(path: &str, writable: bool) -> Result<Self> {
        let (root, _) = preopens::get_directories()
            .into_iter()
            .find(|(_, name)| name == "/")
            .ok_or(Error::MissingRoot)?;
        let relative = path.trim_start_matches('/');
        let descriptor = root
            .open_at(
                PathFlags::SYMLINK_FOLLOW,
                relative.to_owned(),
                OpenFlags::empty(),
                if writable {
                    DescriptorFlags::READ | DescriptorFlags::WRITE
                } else {
                    DescriptorFlags::READ
                },
            )
            .await?;
        let size = descriptor.stat().await?.size;
        Ok(Self { descriptor, size })
    }

    pub const fn size(&self) -> u64 {
        self.size
    }

    pub const fn descriptor(&self) -> &Descriptor {
        &self.descriptor
    }

    /// Streams the complete file into `memory` at `address` and explicitly
    /// publishes the written guest range.
    pub async fn load_into<B: MemoryBackend>(
        &self,
        memory: &GuestRegion<B>,
        address: GuestPhysAddr,
    ) -> Result<()> {
        let loaded = memory
            .load_wasi_descriptor(address, &self.descriptor, self.size)
            .await?;
        memory.publish(address, loaded)?;
        Ok(())
    }

    /// Reads up to [`TRANSFER_CHUNK_BYTES`] bytes at `offset`.
    pub async fn read_range(&self, offset: u64, length: usize) -> Result<Vec<u8>> {
        if length > TRANSFER_CHUNK_BYTES
            || offset
                .checked_add(length as u64)
                .is_none_or(|end| end > self.size)
        {
            return Err(Error::FileRange { offset, length });
        }
        if length == 0 {
            return Ok(Vec::new());
        }
        let (mut stream, completion) = self.descriptor.read_via_stream(offset);
        let mut bytes = Vec::with_capacity(length);
        while bytes.len() < length {
            let (status, next) = stream.read(bytes).await;
            bytes = next;
            if helios_api::stream_closed(status) && bytes.len() < length {
                return Err(Error::ShortRead);
            }
        }
        drop(stream);
        // Bounded reads intentionally close before EOF; dropping cancels the unused suffix.
        drop(completion);
        Ok(bytes)
    }

    /// Writes `bytes` at `offset`, bounded to the existing file length.
    pub async fn write_range(&self, offset: u64, bytes: Vec<u8>) -> Result<()> {
        if offset
            .checked_add(bytes.len() as u64)
            .is_none_or(|end| end > self.size)
        {
            return Err(Error::FileRange {
                offset,
                length: bytes.len(),
            });
        }
        if bytes.is_empty() {
            return Ok(());
        }
        let (mut tx, rx) = helios_api::bindings::wit_stream::new();
        let (written, remainder) = zip(
            async { self.descriptor.write_via_stream(rx, offset).await },
            async move {
                let rest = tx.write_all(bytes).await;
                drop(tx);
                rest
            },
        )
        .await;
        written?;
        if !remainder.is_empty() {
            return Err(Error::ShortWrite);
        }
        Ok(())
    }
}

impl BlockBackend for WasiFile {
    fn size(&self) -> u64 {
        self.size
    }

    async fn read(&self, offset: u64, length: usize) -> Result<Vec<u8>> {
        self.read_range(offset, length).await
    }

    async fn write(&self, offset: u64, bytes: Vec<u8>) -> Result<()> {
        self.write_range(offset, bytes).await
    }
}
