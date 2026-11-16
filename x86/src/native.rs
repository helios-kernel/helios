//! Hardware-isolated native execution, independent of any userspace ABI.
//!
//! One owner holds both a context and its address space while running. Page
//! tables are mutated only while inactive. Every entry and exit writes CR3
//! without PCID or global user mappings, so no CPU retains a usable translation
//! after an execution slice. The owner may migrate only between slices. Kernel
//! upper-half tables are shared; userspace owns only its private lower half.

use alloc::alloc::{Layout, alloc_zeroed, dealloc};
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::arch::global_asm;
use core::ptr::NonNull;

use helios_kernel::{allocate_user_frame_zeroed_on, deallocate_user_frame_on};
use x86::msr::{rdmsr, wrmsr};
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::{
    FrameAllocator, Mapper, OffsetPageTable, Page, PageTable, PageTableFlags, PhysFrame, Size4KiB,
};
use x86_64::{PhysAddr, VirtAddr};

use crate::{exceptions, extended_state, smp};

// GDT: null, kernel code/data, user data/code. RPL is three for user selectors.
pub(crate) const USER_DATA: u16 = 3 * 8 + 3;
pub(crate) const USER_CODE: u16 = 4 * 8 + 3;
const PAGE_BYTES: usize = 4096;
const USER_END: u64 = 1 << 47;
// AMD64 architectural MSR numbers, also specified by Intel SDM volume 4.
const EFER: u32 = 0xc000_0080;
const STAR: u32 = 0xc000_0081;
const LSTAR: u32 = 0xc000_0082;
const FMASK: u32 = 0xc000_0084;
const FS_BASE: u32 = 0xc000_0100;
const GS_BASE: u32 = 0xc000_0101;
const KERNEL_GS_BASE: u32 = 0xc000_0102;
const SYSCALL_VECTOR: u64 = 256;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("native address range is outside the user half or overlaps a mapping")]
    Address,
    #[error("native user frames exhausted")]
    OutOfMemory,
    #[error("native page-table mapping failed")]
    Mapping,
}

struct UserPage {
    address: u64,
    frame: NonNull<u8>,
}

struct Tables {
    frames: Vec<Box<PageTable>>,
    offset: usize,
}

// SAFETY: each allocation is a fresh aligned, zeroed table retained until the
// inactive address space is dropped. No frame is allocated twice.
unsafe impl FrameAllocator<Size4KiB> for Tables {
    fn allocate_frame(&mut self) -> Option<PhysFrame> {
        let table = Box::new(PageTable::new());
        let physical = (&*table as *const PageTable as usize).checked_sub(self.offset)?;
        let frame =
            PhysFrame::<Size4KiB>::from_start_address(PhysAddr::new(physical as u64)).ok()?;
        self.frames.push(table);
        Some(frame)
    }
}

pub struct AddressSpace {
    root: Box<PageTable>,
    tables: Tables,
    pages: Vec<UserPage>,
}

// SAFETY: all access is through exclusive ownership, with no active CR3 across
// a move. Frame reclamation uses the allocator's cross-processor free path.
unsafe impl Send for AddressSpace {}
// SAFETY: read only copies immutable owned pages; execution requires &mut self.
unsafe impl Sync for AddressSpace {}

impl Default for AddressSpace {
    fn default() -> Self {
        Self::new()
    }
}

impl AddressSpace {
    pub fn new() -> Self {
        Self {
            root: Box::new(PageTable::new()),
            tables: Tables {
                frames: Vec::new(),
                offset: smp::current_runtime().physical_memory_offset,
            },
            pages: Vec::new(),
        }
    }

    /// Installs private zero-filled pages, then copies the supplied bytes. The
    /// caller drops the whole inactive space on failure (partial mappings are
    /// retained and owned until then). W+X is not supported by this prototype.
    pub fn map(
        &mut self,
        address: u64,
        size: u64,
        data: &[u8],
        writable: bool,
        executable: bool,
    ) -> Result<(), Error> {
        let end = address.checked_add(size).ok_or(Error::Address)?;
        if address < PAGE_BYTES as u64
            || end > USER_END
            || data.len() as u64 > size
            || size == 0
            || writable && executable
        {
            return Err(Error::Address);
        }
        let first = address & !(PAGE_BYTES as u64 - 1);
        let last = (end + PAGE_BYTES as u64 - 1) & !(PAGE_BYTES as u64 - 1);
        if self
            .pages
            .iter()
            .any(|page| (first..last).contains(&page.address))
        {
            return Err(Error::Address);
        }
        let mut flags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
        if writable {
            flags |= PageTableFlags::WRITABLE;
        }
        if !executable {
            flags |= PageTableFlags::NO_EXECUTE;
        }
        for base in (first..last).step_by(PAGE_BYTES) {
            let raw = allocate_user_frame_zeroed_on(smp::current_processor())
                .map_err(|_| Error::OutOfMemory)?;
            self.pages.push(UserPage {
                address: base,
                frame: raw,
            });
            let physical = raw.as_ptr() as usize - self.tables.offset;
            let frame = PhysFrame::<Size4KiB>::from_start_address(PhysAddr::new(physical as u64))
                .expect("user allocator returns aligned frames");
            let page =
                Page::<Size4KiB>::from_start_address(VirtAddr::new(base)).expect("page aligned");
            // SAFETY: the root and all lower-half tables are owned exclusively;
            // each frame is fresh, and the kernel direct map reaches every table.
            unsafe {
                let mut mapper =
                    OffsetPageTable::new(&mut self.root, VirtAddr::new(self.tables.offset as u64));
                mapper
                    .map_to(page, frame, flags, &mut self.tables)
                    .map_err(|_| Error::Mapping)?
                    .ignore();
            }
            let copy_start = base.max(address);
            let copy_end = (base + PAGE_BYTES as u64).min(address + data.len() as u64);
            if copy_start < copy_end {
                let source = &data[(copy_start - address) as usize..(copy_end - address) as usize];
                // SAFETY: copy is confined to this freshly allocated page.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        source.as_ptr(),
                        raw.as_ptr().add((copy_start - base) as usize),
                        source.len(),
                    );
                }
            }
        }
        Ok(())
    }

    /// Copies through owned frame aliases, never through unchecked user pointers.
    pub fn read(&self, address: u64, output: &mut [u8]) -> Result<(), Error> {
        let end = address
            .checked_add(output.len() as u64)
            .ok_or(Error::Address)?;
        if end > USER_END {
            return Err(Error::Address);
        }
        let mut done = 0;
        while done < output.len() {
            let cursor = address + done as u64;
            let base = cursor & !(PAGE_BYTES as u64 - 1);
            let page = self
                .pages
                .iter()
                .find(|page| page.address == base)
                .ok_or(Error::Address)?;
            let offset = (cursor - base) as usize;
            let length = (PAGE_BYTES - offset).min(output.len() - done);
            // SAFETY: the immutable space owns this entire physical frame and
            // cannot run or unmap while borrowed for this copy.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    page.frame.as_ptr().add(offset),
                    output[done..].as_mut_ptr(),
                    length,
                );
            }
            done += length;
        }
        Ok(())
    }

    fn cr3(&mut self) -> u64 {
        let kernel = Cr3::read().0.start_address().as_u64() as usize + self.tables.offset;
        // SAFETY: the current CR3 is a live kernel root, mapped through HHDM.
        let kernel = unsafe { &*(kernel as *const PageTable) };
        for index in 256..512 {
            self.root[index] = kernel[index].clone();
        }
        &*self.root as *const PageTable as u64 - self.tables.offset as u64
    }
}

impl Drop for AddressSpace {
    fn drop(&mut self) {
        // No execution slice outlives the exclusive borrow of this space. All
        // user translations were flushed by the switch back to the kernel CR3.
        for page in self.pages.drain(..) {
            deallocate_user_frame_on(smp::current_processor(), page.frame);
        }
    }
}

/// Hardware register order shared with the exception entry stubs.
#[derive(Default, Debug)]
#[repr(C)]
pub struct Registers {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rax: u64,
    vector: u64,
    error: u64,
    pub rip: u64,
    cs: u64,
    rflags: u64,
    pub rsp: u64,
    ss: u64,
}

struct AlignedBytes {
    pointer: NonNull<u8>,
    layout: Layout,
}
impl AlignedBytes {
    fn new(size: usize, align: usize) -> Result<Self, Error> {
        let layout = Layout::from_size_align(size, align).expect("native allocation layout");
        // SAFETY: layout is nonempty and valid; Drop uses the same layout.
        let pointer = NonNull::new(unsafe { alloc_zeroed(layout) }).ok_or(Error::OutOfMemory)?;
        Ok(Self { pointer, layout })
    }
}
impl Drop for AlignedBytes {
    fn drop(&mut self) {
        unsafe {
            dealloc(self.pointer.as_ptr(), self.layout);
        }
    }
}
// SAFETY: uniquely owned storage, with no active assembly use across a move.
unsafe impl Send for AlignedBytes {}

#[repr(C)]
struct Switch {
    registers: Registers,
    user_xstate: u64,
    kernel_xstate: u64,
    kernel_rsp: u64,
    kernel_cr3: u64,
    kernel_fs: u64,
    kernel_gs: u64,
    entry_stack: u64,
    scratch_rsp: u64,
    user_cr3: u64,
    self_pointer: u64,
}

pub struct Context {
    switch: Switch,
    _user_xstate: AlignedBytes,
    _kernel_xstate: AlignedBytes,
    _entry_stack: AlignedBytes,
}

#[derive(Debug)]
pub enum Stop {
    SystemCall,
    Interrupted,
    Preempted,
    Fault {
        vector: u64,
        error: u64,
        instruction: u64,
    },
}

impl Context {
    pub fn new(entry: u64, stack: u64) -> Result<Self, Error> {
        if !(PAGE_BYTES as u64..USER_END).contains(&entry)
            || !(PAGE_BYTES as u64..USER_END).contains(&stack)
        {
            return Err(Error::Address);
        }
        let size = extended_state::xsave_sizes().0 as usize;
        let user = AlignedBytes::new(size, 64)?;
        let kernel = AlignedBytes::new(size, 64)?;
        let entry_stack = AlignedBytes::new(exceptions::EXCEPTION_STACK_BYTES, 16)?;
        // The all-zero XSAVE header restores architectural initial state.
        Ok(Self {
            switch: Switch {
                registers: Registers {
                    rip: entry,
                    rsp: stack,
                    cs: USER_CODE as u64,
                    ss: USER_DATA as u64,
                    rflags: 0x202,
                    ..Registers::default()
                },
                user_xstate: user.pointer.as_ptr() as u64,
                kernel_xstate: kernel.pointer.as_ptr() as u64,
                kernel_rsp: 0,
                kernel_cr3: 0,
                kernel_fs: 0,
                kernel_gs: 0,
                entry_stack: entry_stack.pointer.as_ptr() as u64 + entry_stack.layout.size() as u64,
                scratch_rsp: 0,
                user_cr3: 0,
                self_pointer: 0,
            },
            _user_xstate: user,
            _kernel_xstate: kernel,
            _entry_stack: entry_stack,
        })
    }

    pub fn registers(&self) -> &Registers {
        &self.switch.registers
    }

    pub fn return_value(&mut self, value: u64) {
        self.switch.registers.rax = value;
    }

    /// Runs until a syscall, fault or external interrupt. The kernel executor
    /// regains control on every timer tick even if the program never calls out.
    pub fn resume(&mut self, space: &mut AddressSpace) -> Stop {
        // SYSCALL can save a noncanonical next RIP or stack. Refuse it before
        // IRET, whose fault would otherwise occur at kernel privilege.
        if self.switch.registers.rip >= USER_END || self.switch.registers.rsp >= USER_END {
            return Stop::Fault {
                vector: 13,
                error: 0,
                instruction: self.switch.registers.rip,
            };
        }
        // Preserve user arithmetic/debug flags, RF, AC and ID. NT, VM, IOPL,
        // VIF/VIP and reserved flags cannot be carried into the kernel's IRET.
        const USER_FLAGS: u64 = (1 << 0)
            | (1 << 2)
            | (1 << 4)
            | (1 << 6)
            | (1 << 7)
            | (1 << 8)
            | (1 << 10)
            | (1 << 11)
            | (1 << 16)
            | (1 << 18)
            | (1 << 21);
        self.switch.registers.rflags = (self.switch.registers.rflags & USER_FLAGS) | 0x202;
        x86_64::instructions::interrupts::without_interrupts(|| unsafe {
            self.switch.user_cr3 = space.cr3();
            self.switch.self_pointer = core::ptr::from_mut(&mut self.switch) as u64;
            let (kernel_frame, kernel_flags) = Cr3::read_raw();
            self.switch.kernel_cr3 =
                kernel_frame.start_address().as_u64() | u64::from(kernel_flags);
            self.switch.kernel_fs = rdmsr(FS_BASE);
            self.switch.kernel_gs = rdmsr(GS_BASE);
            let old_kernel_gs = rdmsr(KERNEL_GS_BASE);
            wrmsr(KERNEL_GS_BASE, self.switch.self_pointer);
            wrmsr(GS_BASE, 0);
            // SYSCALL loads kernel CS=8 and SS=16; return uses IRET, not SYSRET.
            wrmsr(STAR, 8 << 32);
            wrmsr(LSTAR, helios_x86_native_syscall as *const () as u64);
            wrmsr(FMASK, u32::MAX as u64);
            wrmsr(EFER, rdmsr(EFER) | 1);
            helios_x86_native_enter(&mut self.switch);
            wrmsr(GS_BASE, self.switch.kernel_gs);
            wrmsr(KERNEL_GS_BASE, old_kernel_gs);
        });
        let frame = &self.switch.registers;
        match frame.vector {
            SYSCALL_VECTOR => Stop::SystemCall,
            vector if vector == exceptions::TIMER_INTERRUPT_VECTOR as u64 => Stop::Preempted,
            32..=255 => Stop::Interrupted,
            vector => Stop::Fault {
                vector,
                error: frame.error,
                instruction: frame.rip,
            },
        }
    }
}

global_asm!(include_str!("native.S"),
    user_data = const USER_DATA,
    user_code = const USER_CODE,
    syscall_vector = const SYSCALL_VECTOR,
    user_xstate = const core::mem::offset_of!(Switch, user_xstate),
    kernel_xstate = const core::mem::offset_of!(Switch, kernel_xstate),
    kernel_rsp = const core::mem::offset_of!(Switch, kernel_rsp),
    kernel_cr3 = const core::mem::offset_of!(Switch, kernel_cr3),
    kernel_fs = const core::mem::offset_of!(Switch, kernel_fs),
    entry_stack = const core::mem::offset_of!(Switch, entry_stack),
    scratch_rsp = const core::mem::offset_of!(Switch, scratch_rsp),
    user_cr3 = const core::mem::offset_of!(Switch, user_cr3),
    self_pointer = const core::mem::offset_of!(Switch, self_pointer),
    frame_words = const core::mem::size_of::<Registers>() / 8,
);

unsafe extern "C" {
    fn helios_x86_native_enter(state: *mut Switch);
    fn helios_x86_native_syscall();
}

#[unsafe(no_mangle)]
extern "C" fn helios_x86_native_interrupt(frame: &mut exceptions::ExceptionFrame) {
    exceptions::helios_x86_interrupt_dispatch(frame);
}
