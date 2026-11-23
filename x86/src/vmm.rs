//! The x86_64 user virtual address space of the running kernel.
//!
//! The address space itself — reservations, the reservation lock and
//! every page-table walk — is [`helios_x86_vmm::X86UserAddressSpace`].
//! This module is the machine it runs on: [`HhdmMachine`] reads `CR3`,
//! reaches physical memory through Limine's higher-half direct map
//! (HHDM), takes table frames from the kernel heap and user frames from
//! the user-memory pool, and invalidates translations with `INVLPG` and
//! the dedicated local-APIC shootdown IPI, which waits for every online
//! processor to acknowledge before old frames return to the pool. It also
//! installs the one address space the image has and the runtime hooks
//! that reach it.

use core::alloc::Layout;
use core::ffi::c_int;
use core::ptr::NonNull;

use helios_hal::vmm::{AddressSpace, AddressSpaceError, PageFlags, VirtAddr, VirtRange};
use helios_kernel::runtime_memory::{
    self, RuntimeMemoryHooks, default_memory_image_free, default_memory_image_map_at,
    default_memory_image_new, default_page_size,
};
use helios_kernel::{
    FiberStackVmHooks, MemoryOwner, ResidencyVmHooks, allocate_user_frame_uninit_on_node,
    allocate_user_frame_zeroed_on, allocate_user_run_zeroed_on, current_user_memory_owner,
    deallocate_user_frame_on, deallocate_user_run_on, install_fiber_stack_hooks,
    install_residency_hooks, residency_vm_hooks, user_frame_node,
};
use helios_x86_vmm::{InstalledMachine, Machine};
use spin::Once;
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::{FrameAllocator, PhysFrame};

use crate::smp::{self, DirectMappedFrameAllocator};

/// The image's user address space: the shared x86 page-table logic over
/// this machine's direct map.
pub type X86UserAddressSpace = helios_x86_vmm::X86UserAddressSpace<HhdmMachine>;

const PAGE: usize = helios_hal::pmm::PhysFrame::SIZE;

/// The running kernel's machine: the tables `CR3` names, physical memory
/// at a fixed offset in the HHDM, and the kernel heap and user pool as
/// frame sources.
pub struct HhdmMachine {
    physical_memory_offset: usize,
}

impl HhdmMachine {
    fn user_frame_pointer(&self, phys: usize) -> NonNull<u8> {
        NonNull::new(self.frame_pointer(phys))
            .unwrap_or_else(|| panic!("x86 user frame {phys:#x} has a null HHDM address"))
    }

    fn physical(&self, pointer: NonNull<u8>) -> usize {
        self.physical_address(pointer).unwrap_or_else(|| {
            panic!(
                "x86 user frame {:#x} lies below the HHDM",
                pointer.as_ptr() as usize
            )
        })
    }
}

// SAFETY: the HHDM maps every byte of physical memory at
// `physical_memory_offset`, so `frame_pointer` reaches every frame the
// tables, the kernel heap and the user pool hold; `allocate_table` takes
// a zeroed frame of the kernel heap, which lives in the HHDM and is never
// given back; and `physical_address` subtracts the offset `frame_pointer`
// adds.
unsafe impl Machine for HhdmMachine {
    fn root_table(&self) -> PhysFrame {
        Cr3::read().0
    }

    fn allocate_table(&self) -> Option<PhysFrame> {
        DirectMappedFrameAllocator {
            physical_memory_offset: self.physical_memory_offset,
        }
        .allocate_frame()
    }

    fn frame_pointer(&self, phys: usize) -> *mut u8 {
        phys.checked_add(self.physical_memory_offset)
            .unwrap_or_else(|| panic!("x86 HHDM address of {phys:#x} overflows")) as *mut u8
    }

    fn physical_address(&self, pointer: NonNull<u8>) -> Option<usize> {
        (pointer.as_ptr() as usize).checked_sub(self.physical_memory_offset)
    }

    fn allocate_frame(&self) -> Result<usize, AddressSpaceError> {
        let raw = allocate_user_frame_zeroed_on(smp::current_processor())
            .map_err(|_| AddressSpaceError::OutOfFrames)?;
        Ok(self.physical(raw))
    }

    fn allocate_frame_beside(&self, phys: usize) -> Result<usize, AddressSpaceError> {
        let node = user_frame_node(self.user_frame_pointer(phys));
        let raw =
            allocate_user_frame_uninit_on_node(node).map_err(|_| AddressSpaceError::OutOfFrames)?;
        Ok(self.physical(raw))
    }

    fn free_frame(&self, phys: usize) {
        deallocate_user_frame_on(smp::current_processor(), self.user_frame_pointer(phys));
    }

    fn allocate_run(&self, layout: Layout) -> Result<usize, AddressSpaceError> {
        let raw = allocate_user_run_zeroed_on(smp::current_processor(), layout)
            .map_err(|_| AddressSpaceError::OutOfFrames)?;
        Ok(self.physical(raw))
    }

    fn free_run(&self, phys: usize, layout: Layout) {
        deallocate_user_run_on(
            smp::current_processor(),
            self.user_frame_pointer(phys),
            layout,
        );
    }

    fn current_owner(&self) -> MemoryOwner {
        current_user_memory_owner(smp::current_processor())
    }

    fn invalidate_local(&self, range: VirtRange) {
        smp::flush_tlb_range_local(range.start.raw(), range.byte_len);
    }

    fn shootdown(&self, range: VirtRange) {
        smp::shootdown_tlb_range(range.start.raw(), range.byte_len);
    }
}

impl InstalledMachine for HhdmMachine {
    fn installed() -> &'static X86UserAddressSpace {
        user_as()
    }
}

/// The kernel's view of how much of the user pool each instance holds.
static X86_RESIDENCY_HOOKS: ResidencyVmHooks = residency_vm_hooks::<X86UserAddressSpace>();

static USER_AS: Once<X86UserAddressSpace> = Once::new();

/// Initialise the boot-time user address space and install the
/// runtime custom-virtual-memory hooks. Must be called once on the
/// bootstrap CPU after Limine handoff is processed and before any
/// runtime engine is constructed.
pub fn install_user_address_space(physical_memory_offset: usize, processor_count: usize) {
    USER_AS.call_once(|| {
        X86UserAddressSpace::new(
            HhdmMachine {
                physical_memory_offset,
            },
            processor_count,
        )
    });
    runtime_memory::install_hooks(&X86_VMM_HOOKS);
    install_residency_hooks(&X86_RESIDENCY_HOOKS);
    install_fiber_stack_hooks(&X86_FIBER_STACK_HOOKS);
}

/// The installed user address space, for the backend's device hooks.
pub(crate) fn user_address_space() -> &'static X86UserAddressSpace {
    user_as()
}

fn user_as() -> &'static X86UserAddressSpace {
    USER_AS
        .get()
        .expect("X86UserAddressSpace accessed before install_user_address_space")
}

/// One reserved user page for `exceptions::verify_page_fault_returns` to
/// fault on, with its leaf page table already in place.
///
/// The probe's fault is resolved from the page-fault dispatcher, and the
/// only address-space operation allowed there is the one a fiber stack's
/// fault takes: `commit_demand_page`, which writes one leaf entry under
/// no lock and broadcasts nothing, because an unmapped-to-mapped
/// transition invalidates no translation anywhere. The dispatcher may
/// have interrupted a holder of the address-space lock, and a TLB
/// shootdown from a context that cannot take the shootdown IPI is what
/// `smp::shootdown_tlb_range` refuses. The locked `commit` the probe used
/// to resolve its fault with did both; bench run 34443906698 stalled its
/// candidate kernel with its fourth processor inside that broadcast.
pub(crate) fn reserve_probe_page() -> VirtRange {
    let range = user_as()
        .reserve(PAGE)
        .unwrap_or_else(|error| panic!("x86 page-fault probe could not reserve a page: {error}"));
    user_as()
        .prepare_demand_commit(range, PageFlags::READ | PageFlags::WRITE)
        .unwrap_or_else(|error| {
            panic!(
                "x86 page-fault probe could not prepare {:#x} for a demand commit: {error}",
                range.start.raw()
            )
        });
    range
}

/// Maps `frame` at the probe's page from the page-fault dispatcher:
/// lock-free and shootdown-free, see `reserve_probe_page`.
pub(crate) fn commit_probe_page(start: usize, frame: NonNull<u8>) {
    user_as()
        .commit_demand_page(
            VirtAddr::new(start),
            frame,
            PageFlags::READ | PageFlags::WRITE,
        )
        .unwrap_or_else(|error| {
            panic!("x86 page-fault probe could not commit {start:#x}: {error}")
        });
}

/// Gives the probe's page and the frame mapped at it back once the probe
/// has read it. Runs with interrupts enabled, where the shootdown the
/// unmap broadcasts can be acknowledged by everyone it reaches.
pub(crate) fn release_probe_page(range: VirtRange) {
    user_as()
        .end_demand_commit(range, range)
        .unwrap_or_else(|error| {
            panic!(
                "x86 page-fault probe could not end the demand commit of {:#x}: {error}",
                range.start.raw()
            )
        });
    user_as().release(range).unwrap_or_else(|error| {
        panic!(
            "x86 page-fault probe could not release {:#x}: {error}",
            range.start.raw()
        )
    });
}

const ENOMEM: c_int = 12;
const EINVAL: c_int = 22;

const PROT_READ: u32 = 1 << 0;
const PROT_WRITE: u32 = 1 << 1;
const PROT_EXEC: u32 = 1 << 2;

fn prot_to_flags(prot: u32) -> PageFlags {
    let mut flags = PageFlags::empty();
    if prot & PROT_READ != 0 {
        flags |= PageFlags::READ;
    }
    if prot & PROT_WRITE != 0 {
        flags |= PageFlags::WRITE;
    }
    if prot & PROT_EXEC != 0 {
        flags |= PageFlags::EXECUTE;
    }
    flags
}

fn round_up_to_page(size: usize) -> usize {
    (size + PAGE - 1) & !(PAGE - 1)
}

extern "C" fn x86_mmap_new(size: usize, prot_flags: u32, ret: &mut *mut u8) -> c_int {
    let size = round_up_to_page(size);
    let address_space = user_as();
    let range = match address_space.reserve(size) {
        Ok(range) => range,
        Err(error) => {
            tracing::error!(
                target: "helios_x86::vmm",
                size,
                prot_flags,
                ?error,
                "mmap_new reserve failed"
            );
            return ENOMEM;
        }
    };
    if prot_flags != 0 {
        let flags = prot_to_flags(prot_flags);
        if let Err(error) = address_space.commit(range, flags) {
            tracing::error!(
                target: "helios_x86::vmm",
                size,
                prot_flags,
                ?error,
                "mmap_new commit failed"
            );
            let _ = address_space.release(range);
            return ENOMEM;
        }
    }
    *ret = range.start.raw() as *mut u8;
    tracing::trace!(
        target: "helios_x86::vmm",
        size,
        prot_flags,
        addr = range.start.raw(),
        "mmap_new ok"
    );
    0
}

extern "C" fn x86_mmap_remap(addr: *mut u8, size: usize, prot_flags: u32) -> c_int {
    // The runtime's `mmap_remap` rebinds an existing mapping to fresh
    // anonymous-zero pages with `prot_flags`. This address space cannot swap
    // to brand-new frames in a single transaction, so the closest faithful
    // sequence is decommit→commit: decommit returns the old frames to the
    // user-memory pool, commit takes fresh zeroed ones and maps them over the
    // same range. The window where the range is uncommitted is invisible to
    // the runtime, which only remaps a slot between instances, with no thread
    // touching it.
    let size = round_up_to_page(size);
    let address_space = user_as();
    let range = VirtRange::new(VirtAddr::new(addr as usize), size);
    if let Err(error) = address_space.decommit_committed_subranges(range) {
        tracing::error!(
            target: "helios_x86::vmm",
            addr = addr as usize,
            size,
            ?error,
            "mmap_remap decommit failed"
        );
        return EINVAL;
    }
    if prot_flags != 0 {
        let flags = prot_to_flags(prot_flags);
        if let Err(error) = address_space.commit(range, flags) {
            tracing::error!(
                target: "helios_x86::vmm",
                addr = addr as usize,
                size,
                prot_flags,
                ?error,
                "mmap_remap commit failed"
            );
            return ENOMEM;
        }
    }
    0
}

extern "C" fn x86_munmap(ptr: *mut u8, size: usize) -> c_int {
    let size = round_up_to_page(size);
    let address_space = user_as();
    let range = VirtRange::new(VirtAddr::new(ptr as usize), size);
    match address_space.release(range) {
        Ok(()) => 0,
        Err(_) => EINVAL,
    }
}

extern "C" fn x86_mprotect(ptr: *mut u8, size: usize, prot_flags: u32) -> c_int {
    let size = round_up_to_page(size);
    let address_space = user_as();
    let range = VirtRange::new(VirtAddr::new(ptr as usize), size);
    if prot_flags == 0 {
        return match address_space.decommit_committed_subranges(range) {
            Ok(()) => 0,
            Err(error) => {
                tracing::error!(
                    target: "helios_x86::vmm",
                    addr = ptr as usize,
                    size,
                    ?error,
                    "mprotect(prot=0) decommit failed"
                );
                EINVAL
            }
        };
    }
    let flags = prot_to_flags(prot_flags);
    match address_space.ensure_accessible_subranges(range, flags) {
        Ok(()) => 0,
        Err(error) => {
            tracing::error!(
                target: "helios_x86::vmm",
                addr = ptr as usize,
                size,
                prot_flags,
                ?error,
                "mprotect failed"
            );
            EINVAL
        }
    }
}

/// Runtime custom-virtual-memory hook table for the x86 backend.
/// Address-space mutations route through the singleton
/// `X86UserAddressSpace`; COW image creation is opted out of
/// (`default_memory_image_new` returns `NULL`), so the runtime falls back to
/// per-instance memcpy initialization.
pub static X86_VMM_HOOKS: RuntimeMemoryHooks = RuntimeMemoryHooks {
    mmap_new: x86_mmap_new,
    mmap_remap: x86_mmap_remap,
    munmap: x86_munmap,
    mprotect: x86_mprotect,
    page_size: default_page_size,
    memory_image_new: default_memory_image_new,
    memory_image_free: default_memory_image_free,
    memory_image_map_at: default_memory_image_map_at,
};

const _: () = {
    // Pin the C ABI so a runtime ABI revision that changes the
    // `RuntimeMemoryImage` opaque ptr type fails the build instead of
    // mismatching at link time.
    let _: extern "C" fn(*const u8, usize, &mut *mut runtime_memory::RuntimeMemoryImage) -> c_int =
        default_memory_image_new;
};

/// The arena's address-space surface for this backend.
///
/// Separate from [`X86_VMM_HOOKS`] because it is a different contract:
/// that one answers the runtime's C mmap ABI, this one is the typed
/// route the kernel's fiber-stack arena takes to the same address
/// space, and one of its entries runs in page-fault context where the
/// other's may not.
static X86_FIBER_STACK_HOOKS: FiberStackVmHooks = FiberStackVmHooks {
    reserve: |bytes| user_as().reserve(bytes),
    prepare_demand_commit: |virt, flags| user_as().prepare_demand_commit(virt, flags),
    commit_demand_page: |addr, frame, flags| user_as().commit_demand_page(addr, frame, flags),
    end_demand_commit: |virt, mapped| user_as().end_demand_commit(virt, mapped),
};
