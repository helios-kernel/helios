use core::ptr::NonNull;
use std::alloc::{AllocError, Allocator, Global, Layout};

use ash::vk::{AllocationCallbacks, SystemAllocationScope};

/// A copied Vulkan allocator contract. Its callback userdata remains valid
/// until every object created with it has been destroyed by the application.
#[derive(Clone, Copy)]
pub(super) struct HostAllocator {
    callbacks: Option<AllocationCallbacks<'static>>,
    scope: SystemAllocationScope,
}

impl HostAllocator {
    /// The caller supplies Vulkan-valid callbacks and their userdata lifetime.
    pub(super) unsafe fn new(
        callbacks: *const AllocationCallbacks<'_>,
        scope: SystemAllocationScope,
    ) -> Self {
        let callbacks = if callbacks.is_null() {
            None
        } else {
            // SAFETY: Vulkan ties the callbacks' userdata to the allocated
            // objects' lifetime, not the create-info structure's borrow.
            Some(unsafe {
                core::mem::transmute::<AllocationCallbacks<'_>, AllocationCallbacks<'static>>(
                    *callbacks,
                )
            })
        };
        Self { callbacks, scope }
    }
}

// SAFETY: Vulkan allocation callbacks may be invoked by any thread making
// an API call. The application is responsible for synchronizing userdata.
unsafe impl Send for HostAllocator {}
// SAFETY: the same Vulkan callback contract permits concurrent allocations.
unsafe impl Sync for HostAllocator {}

// SAFETY: allocations preserve the requested alignment and use the paired
// callback for deallocation. Copies retain the same userdata and callbacks.
unsafe impl Allocator for HostAllocator {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        let pointer = match self.callbacks {
            Some(callbacks) => {
                // SAFETY: construction requires Vulkan-valid callbacks.
                let pointer = unsafe {
                    callbacks.pfn_allocation.unwrap()(
                        callbacks.p_user_data,
                        layout.size(),
                        layout.align(),
                        self.scope,
                    )
                };
                NonNull::new(pointer.cast()).ok_or(AllocError)?
            }
            None => return Global.allocate(layout),
        };
        Ok(NonNull::slice_from_raw_parts(pointer, layout.size()))
    }

    unsafe fn deallocate(&self, pointer: NonNull<u8>, layout: Layout) {
        match self.callbacks {
            Some(callbacks) => {
                // SAFETY: Allocator's caller returns an allocation from
                // this callback pair, and construction validates its lifetime.
                unsafe {
                    callbacks.pfn_free.unwrap()(callbacks.p_user_data, pointer.as_ptr().cast())
                };
            }
            None => {
                // SAFETY: the allocation was obtained from Global above.
                unsafe { Global.deallocate(pointer, layout) };
            }
        }
    }
}
