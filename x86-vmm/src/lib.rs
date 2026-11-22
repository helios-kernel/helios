//! The x86-64 user address space, apart from the machine it runs on.
//!
//! [`X86UserAddressSpace`] is the backend's whole `hal::vmm::AddressSpace`:
//! the reservation tracker, the lock that serialises the address space's
//! table mutations, and every walk that builds, rewrites or clears a
//! four-level page table. What it does not own is the hardware: where the
//! root table is, how a physical address is reached, where table and user
//! frames come from, and how a translation is invalidated. A [`Machine`]
//! answers those. The bare-metal backend's machine reads `CR3`, reaches
//! physical memory through the bootloader's direct map, takes frames from
//! the kernel heap and the user pool, and invalidates with `INVLPG` and the
//! shootdown IPI. A host test's machine hands out host memory and has no
//! TLB, so the same table code runs under real threads where
//! `just test-units` reaches it.

#![no_std]

extern crate alloc;

mod address_space;
pub mod memory_type;

use core::alloc::Layout;
use core::ptr::NonNull;

use helios_hal::vmm::{AddressSpaceError, VirtRange};
use helios_kernel::MemoryOwner;
use x86_64::structures::paging::PhysFrame;

pub use address_space::{USER_VA_BASE, USER_VA_END, X86UserAddressSpace};

/// What an [`X86UserAddressSpace`] needs from the machine it runs on.
///
/// Physical addresses are `usize` byte addresses, as the address space's
/// leaves hold them. A user frame is one 4 KiB frame; a run is one
/// physically contiguous allocation of the layout it was asked for.
///
/// # Concurrency
///
/// Every method is called from any processor, with or without the address
/// space's reservation lock held, and none of them may take that lock.
///
/// # Safety
///
/// The address space dereferences what [`Machine::frame_pointer`]
/// returns, so an implementation guarantees:
///
/// - for every physical address inside a frame or run that
///   [`Machine::root_table`], [`Machine::allocate_table`],
///   [`Machine::allocate_frame`], [`Machine::allocate_frame_beside`] or
///   [`Machine::allocate_run`] produced, or that a caller of
///   `substitute_memory` or `substitute_device` names, `frame_pointer`
///   returns a pointer through which those bytes are readable and
///   writable for as long as the frame is not given back;
/// - [`Machine::allocate_table`] returns a zeroed frame nothing else uses,
///   and a table frame is never reclaimed while the address space lives;
/// - [`Machine::physical_address`] is the inverse of `frame_pointer`.
pub unsafe trait Machine: Send + Sync + 'static {
    /// The level-4 table of the address space the executing processor
    /// runs in.
    fn root_table(&self) -> PhysFrame;

    /// A zeroed frame for a page table, or `None` when none is left.
    fn allocate_table(&self) -> Option<PhysFrame>;

    /// Where the byte at physical address `phys` is reached.
    fn frame_pointer(&self, phys: usize) -> *mut u8;

    /// The physical address of `pointer`, a [`Machine::frame_pointer`]
    /// answer, or `None` when it is not one.
    fn physical_address(&self, pointer: NonNull<u8>) -> Option<usize>;

    /// One zeroed user frame, taken in the executing processor's name.
    fn allocate_frame(&self) -> Result<usize, AddressSpaceError>;

    /// One user frame from the memory node the frame at `phys` is on, not
    /// zeroed: the caller overwrites all of it.
    fn allocate_frame_beside(&self, phys: usize) -> Result<usize, AddressSpaceError>;

    /// Gives back a frame from [`Machine::allocate_frame`] or
    /// [`Machine::allocate_frame_beside`].
    fn free_frame(&self, phys: usize);

    /// One zeroed, physically contiguous run of user memory laid out as
    /// `layout`.
    fn allocate_run(&self, layout: Layout) -> Result<usize, AddressSpaceError>;

    /// Gives back a run from [`Machine::allocate_run`], with the layout it
    /// was allocated with.
    fn free_run(&self, phys: usize, layout: Layout);

    /// The owner a page committed on the executing processor right now is
    /// charged to.
    fn current_owner(&self) -> MemoryOwner;

    /// Drops the executing processor's translations for `range`.
    fn invalidate_local(&self, range: VirtRange);

    /// Drops every other processor's translations for `range`, returning
    /// once each has acknowledged.
    fn shootdown(&self, range: VirtRange);
}

/// A [`Machine`] with one address space installed for the whole image,
/// which the kernel's trap-context hooks reach without holding it.
pub trait InstalledMachine: Machine + Sized {
    /// The image's address space. A load of an initialised static and
    /// nothing more: it is called from trap context.
    fn installed() -> &'static X86UserAddressSpace<Self>;
}
