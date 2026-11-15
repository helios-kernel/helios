//! Helios transport with canonical stack suspension at Vulkan entry points.

#[cfg(all(target_arch = "wasm32", not(target_feature = "atomics")))]
compile_error!("the Venus shared ring requires -Ctarget-feature=+atomics");

use core::num::NonZeroU64;
use core::ptr::NonNull;

use helios_api::memory::{Block, BlockError};

use crate::capset::{self, Capset, CapsetError};
use crate::transport::{MappedBlob, Transport};

mod bindings {
    wit_bindgen::generate!({
        path: "../wit",
        world: "gpu-host",
        generate_all,
        async: false,
    });
}

use bindings::helios::system::{gpu, memory};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("GPU transport refused: {0}")]
    Gpu(#[from] gpu::Error),
    #[error(transparent)]
    Memory(#[from] BlockError),
    #[error(transparent)]
    Capset(#[from] CapsetError),
}

/// A Venus context. The context resource drops before the GPU session.
pub struct Context {
    context: gpu::Context,
    gpu: gpu::Gpu,
}

impl Context {
    pub fn open(rings: u8, name: &str) -> Result<(Self, Capset), Error> {
        let gpu = gpu::open()?;
        let capset = Capset::decode(&gpu.capset(capset::ID, capset::VERSION)?)?;
        let context = gpu.create_context(capset::ID, rings, name)?;
        Ok((Self { context, gpu }, capset))
    }
}

/// The resource drops before the guest pages, restoring their ordinary
/// backing before the allocator can reuse the virtual address range.
pub struct Blob {
    resource: gpu::Blob,
    mapping: Block,
    pointer: NonNull<u8>,
}

// SAFETY: `mapping` owns aligned guest pages. The resource's destruction
// removes every mapping before those pages are freed. `pointer` is obtained
// once, before renderer ownership; no slice is subsequently made here.
unsafe impl MappedBlob for Blob {
    fn resource_id(&self) -> u32 {
        self.resource.resource_id()
    }

    fn pointer(&self) -> NonNull<u8> {
        self.pointer
    }

    fn len(&self) -> usize {
        self.mapping.len()
    }
}

impl Transport for Context {
    type Error = Error;
    type Blob = Blob;

    fn create_blob(&mut self, size: NonZeroU64, blob_id: u64) -> Result<Blob, Error> {
        let mut mapping = Block::zeroed(size.get())?;
        // Derive the pointer before device memory replaces these pages.
        let pointer = NonNull::new(mapping.bytes_mut().as_mut_ptr()).expect("Block is nonempty");
        let span = mapping.span();
        let resource = self.gpu.create_blob(
            &self.context,
            gpu::BlobMemory::Host3d,
            gpu::BlobUsage::MAPPABLE,
            size.get(),
            blob_id,
            None,
        )?;
        self.context.attach(&resource)?;
        resource.map_blob(memory::Span {
            offset: span.offset,
            length: span.length,
        })?;
        Ok(Blob {
            resource,
            mapping,
            pointer,
        })
    }

    fn execute(&mut self, commands: &[u8], ring: u8, fence: Option<u64>) -> Result<(), Error> {
        self.context
            .execute(commands, ring, fence)
            .map_err(Error::from)
    }

    fn wait(&mut self, ring: u8, fence: u64) -> Result<(), Error> {
        self.context.wait(ring, fence).map_err(Error::from)
    }
}
