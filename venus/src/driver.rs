//! Vulkan entry dispatch backed by instance-owned renderer connections.
//!
//! Each instance serializes its command stream and object registry through
//! a suspension-capable submission lock. Different instances are independent.
//! Only the Vulkan ABI boundary acquires this lock; ordinary SDK calls stay
//! asynchronous. There is no process-global registry or current connection.

mod allocator;
mod chain;
mod command;
mod device;
mod exclusive;
mod external;
mod instance;
mod memory;
mod sync;

#[cfg(feature = "helios")]
pub(crate) use device::completion;
#[cfg(feature = "helios")]
pub(crate) use memory::with_blob;

#[expect(
    non_snake_case,
    reason = "generated Vulkan entry points retain the registry's C names and signatures; all pointer access follows the entry caller's Vulkan contract"
)]
mod generated {
    use super::Factory;
    use crate::protocol::*;
    use crate::runtime::*;
    include!(concat!(env!("OUT_DIR"), "/entry.rs"));
}

use core::num::NonZeroU32;
use core::time::Duration;

use crate::ring::Layout;

use crate::transport::{Transport, TransportFactory};

/// Lock acquisition at the synchronous Vulkan ABI boundary.
///
/// # Safety
/// Guards are mutually exclusive across threads, acquire prior releases,
/// and release on drop. The implementation must suspend through its host
/// scheduler on contention, never spin or block an executor thread.
pub unsafe trait SubmissionLock: Send + Sync {
    type Guard<'a>
    where
        Self: 'a;

    fn new() -> Self;
    fn lock(&self) -> Self::Guard<'_>;
}

/// A transport factory with synchronization for an instance's command stream.
pub trait Factory:
    TransportFactory<Transport: Send + 'static + Transport<Blob: Send, Error: Send>> + 'static
{
    type Lock: SubmissionLock;

    fn configuration() -> Configuration {
        Configuration::default()
    }
}

/// Ring settings for a connection. A factory may read these from its
/// runtime configuration; explicit-transport construction supplies them itself.
pub struct Configuration {
    pub layout: Layout,
    pub idle_timeout: Duration,
}

impl Default for Configuration {
    fn default() -> Self {
        Self {
            // One wasm page of command bytes; larger commands use uploads.
            layout: Layout::new(NonZeroU32::new(65536).unwrap()).unwrap(),
            idle_timeout: Duration::from_millis(1),
        }
    }
}

/// Construct ash's statically linked entry table without global driver state.
pub fn entry<F: Factory>() -> ash::Entry {
    // SAFETY: these monomorphised entry points live for the program's
    // lifetime and obtain every renderer connection from F or a live handle.
    unsafe {
        ash::Entry::from_static_fn(ash::StaticFn {
            get_instance_proc_addr: instance::get_instance_proc_addr::<F>,
        })
    }
}

/// Create a Vulkan instance on an explicitly owned renderer connection.
///
/// This consumes the connection without calling the factory. The resulting
/// instance owns it until `ash::Instance::destroy_instance`; child handles use
/// the same dispatch table as instances created through [`entry`].
///
/// # Safety
/// `info` and `allocator` must satisfy Vulkan's instance creation contract.
/// Callback userdata must outlive the instance and every child allocation.
/// The caller must destroy all children before destroying the instance.
pub unsafe fn instance_from_connection<F: Factory>(
    connection: crate::connection::Connection<F::Transport>,
    info: &ash::vk::InstanceCreateInfo<'_>,
    allocator: Option<&ash::vk::AllocationCallbacks<'_>>,
) -> Result<ash::Instance, ash::vk::Result> {
    let mut handle = ash::vk::Instance::null();
    // SAFETY: the caller supplies Vulkan-valid inputs; handle is writable.
    unsafe {
        instance::create_on_connection::<F>(
            connection,
            info,
            allocator.map_or(core::ptr::null(), |allocator| allocator),
            &mut handle,
        )
    }
    .result()?;
    // SAFETY: `create_on_connection` succeeded and produced a live instance
    // handle dispatched by `entry::<F>()`.
    Ok(unsafe { ash::Instance::load(entry::<F>().static_fn(), handle) })
}
