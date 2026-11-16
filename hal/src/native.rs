//! Native user execution: code compiled for the processor's own instruction
//! set, run at its lowest privilege level in an address space of its own.
//!
//! The contract names hardware properties only: isolated user address
//! spaces, a user register context that runs until the processor leaves
//! user mode, and the reason it left. Which userspace ABI the code speaks
//! (Linux's syscall numbers, its errno values, its signal frames) is the
//! consumer's business, decoded from the architectural registers this
//! contract exposes.
//!
//! # Consumers
//!
//! The kernel's Linux process host is the first: it maps an ELF image,
//! builds the initial stack, resumes a context until it stops, and answers
//! each system call. The shape also carries what comes next on the same
//! surface: removing and narrowing mappings with a cross-processor
//! shootdown, several threads of one process running on several processors
//! in one space, signal delivery that saves and restores the complete
//! register and extended state, and copy-on-write duplication of a space.
//!
//! # Concurrency contract
//!
//! - A [`UserSpace`] is shared: every thread of a process resumes its own
//!   context against the same space, on any processor, at the same time.
//!   Every operation takes `&self`. Operations that change the page tables
//!   serialise on a per-space spin lock held for the walk alone, never
//!   across an `.await` and never reached from interrupt context.
//! - Mapping only makes not-present pages present, which no processor can
//!   have cached, so it needs no shootdown and is visible to every slice
//!   that starts after it returns. An operation that removes a translation
//!   or narrows its permissions must invalidate it on every processor that
//!   has run a slice of the space since the translation was installed, and
//!   free nothing it removed until each of them has acknowledged.
//! - [`UserSpace::read`] and [`UserSpace::write`] copy through the kernel's
//!   own mapping of the backing frames, never through a user address. They
//!   may run while slices of the same space run elsewhere; user code sees
//!   the bytes as it would another thread's stores.
//! - A [`UserContext`] is single-owner: `Send`, never `Sync`, one slice at a
//!   time. [`UserContext::resume`] runs on the calling processor and returns
//!   with no processor-local state of the context left installed (address
//!   space root, thread pointer, system-call entry, extended state), so the
//!   owner may move the context to another processor between slices.
//! - A slice is bounded. It ends at the first interrupt the processor
//!   takes, its timer included, and a backend publishes this capability only
//!   when its timer interrupts every processor at a bounded period whatever
//!   user code does. A program that never traps therefore cannot hold a
//!   processor, and the context's owner observes every pending event within
//!   one timer period.
//! - `resume` is called from task context with interrupts enabled. It
//!   occupies its processor for at most one slice and does not suspend.
//! - Every register a slice can change, general, flags, vector and every
//!   extended-state component the processor enables for user mode, is saved
//!   when the slice ends and restored when the next one starts; the kernel's
//!   own state is saved and restored around the slice the same way.

use core::convert::Infallible;

use thiserror::Error;

use crate::hv::RegisterId;
use crate::vmm::{PageFlags, VirtAddr, VirtRange};

/// The instruction set a native program is compiled for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstructionSet {
    X86_64,
    Aarch64,
    Riscv64,
}

/// Why a native operation was refused. Every refusal leaves the space or
/// context it was asked of unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum NativeError {
    #[error("address range is empty, wraps, or lies outside the user range")]
    Address,
    #[error("range overlaps an existing user mapping")]
    Overlap,
    #[error("the permission combination is refused (writable and executable)")]
    Permissions,
    #[error("user memory is exhausted")]
    OutOfMemory,
    #[error("an address in the range is not mapped with the required access")]
    NotMapped,
    #[error("the register does not exist on this instruction set")]
    Register,
}

/// What a user slice ran into when it ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stop {
    /// The program executed the system-call instruction. Its arguments are
    /// in the context's registers, and the context resumes after it.
    SystemCall,
    /// The processor's timer interrupt ended the slice.
    Preempted,
    /// Any other interrupt ended the slice. The program did nothing.
    Interrupted,
    /// The program faulted. The context resumes at the faulting
    /// instruction, which faults again unless its cause was removed.
    Fault(UserFault),
}

/// A synchronous exception user code raised.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserFault {
    pub kind: FaultKind,
    /// The faulting instruction.
    pub instruction: VirtAddr,
}

/// The class of a user fault, in the terms userspace ABIs deliver them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultKind {
    /// An access the address space refused.
    Page {
        address: VirtAddr,
        /// The access attempted: exactly one of read, write or execute.
        access: PageFlags,
        /// Whether a translation existed and refused the access, rather
        /// than no translation existing at all.
        present: bool,
    },
    /// An undefined or unavailable instruction.
    InvalidInstruction,
    /// An integer division fault or an unmasked floating-point exception.
    Arithmetic,
    /// A breakpoint instruction or a debug trap.
    Breakpoint,
    /// A privileged or protection-violating instruction, a non-canonical
    /// address, or a control-flow-protection violation.
    Protection,
    /// A misaligned access the processor refused.
    Alignment,
}

/// The platform's native execution capability. [`crate::cpu::Cpu::native`]
/// exposes it only when every property the module docs state holds;
/// platforms without it use the uninhabited `Infallible` implementation.
pub trait NativeExecution: Send + Sync + 'static {
    type Space: UserSpace;
    type Context: UserContext<Space = Self::Space>;

    fn instruction_set(&self) -> InstructionSet;

    /// The addresses user code can map: the lowest page above the null
    /// guard up to the end of the user half.
    fn user_range(&self) -> VirtRange;

    /// An empty space: the kernel's half is present and inaccessible to
    /// user code, the user half has no mapping.
    fn create_space(&self) -> Result<Self::Space, NativeError>;

    /// A context whose first slice starts at `entry` with `stack` as its
    /// stack pointer, every other register in its architectural initial
    /// state.
    fn create_context(
        &self,
        entry: VirtAddr,
        stack: VirtAddr,
    ) -> Result<Self::Context, NativeError>;
}

/// A user address space. See the module docs for its concurrency contract.
///
/// # Safety
///
/// No user mapping aliases kernel memory or a frame another space owns, and
/// a page is reachable from user mode only with the flags it was mapped
/// with. Dropping a space releases its frames; the caller's borrow during
/// [`UserContext::resume`] guarantees no slice of it is running then.
pub unsafe trait UserSpace: Send + Sync + 'static {
    /// Installs zero-filled private pages covering `range` with `flags`,
    /// then copies `contents` to `range.start`. `range` need not be page
    /// aligned; every page it touches is installed. Fails, mapping nothing,
    /// when `contents` is longer than the range, any covered page is
    /// already mapped, or `flags` asks for write and execute together.
    fn map(&self, range: VirtRange, contents: &[u8], flags: PageFlags) -> Result<(), NativeError>;

    /// Installs `byte_len` bytes (a page multiple) of zero-filled private
    /// pages at the first free range at or above `hint`, else at the first
    /// free range of the user range, and returns where.
    fn map_anywhere(
        &self,
        hint: VirtAddr,
        byte_len: usize,
        flags: PageFlags,
    ) -> Result<VirtRange, NativeError>;

    /// Copies `output.len()` bytes mapped readable starting at `address`.
    fn read(&self, address: VirtAddr, output: &mut [u8]) -> Result<(), NativeError>;

    /// Whether `byte_len` bytes from `address` are mapped writable.
    fn check_writable(&self, address: VirtAddr, byte_len: usize) -> Result<(), NativeError>;

    /// Copies `bytes` to `address`, which must be mapped writable over the
    /// whole length; nothing is written otherwise.
    fn write(&self, address: VirtAddr, bytes: &[u8]) -> Result<(), NativeError>;
}

/// One thread of user execution. See the module docs for its concurrency
/// contract.
///
/// # Safety
///
/// `resume` enters user mode only with `space`'s translations and leaves
/// none of the context's processor-local state installed when it returns.
/// No register write lets user code run with more privilege than user mode
/// or with a kernel address as its next instruction or stack.
pub unsafe trait UserContext: Send + 'static {
    type Space: UserSpace;

    /// A register of the detached snapshot.
    fn register(&self, register: RegisterId) -> Result<u64, NativeError>;

    /// Replaces a register of the detached snapshot. Flag bits user mode
    /// cannot hold are cleared when the next slice starts.
    fn set_register(&mut self, register: RegisterId, value: u64) -> Result<(), NativeError>;

    /// The thread pointer user code addresses its thread-local storage by.
    fn thread_pointer(&self) -> VirtAddr;

    /// Replaces the thread pointer; refused outside the user range.
    fn set_thread_pointer(&mut self, address: VirtAddr) -> Result<(), NativeError>;

    /// Runs one slice against `space`.
    fn resume(&mut self, space: &Self::Space) -> Stop;
}

impl NativeExecution for Infallible {
    type Space = Self;
    type Context = Self;
    fn instruction_set(&self) -> InstructionSet {
        match *self {}
    }
    fn user_range(&self) -> VirtRange {
        match *self {}
    }
    fn create_space(&self) -> Result<Self, NativeError> {
        match *self {}
    }
    fn create_context(&self, _: VirtAddr, _: VirtAddr) -> Result<Self, NativeError> {
        match *self {}
    }
}

// SAFETY: no value of this type exists, so none of these methods can run.
unsafe impl UserSpace for Infallible {
    fn map(&self, _: VirtRange, _: &[u8], _: PageFlags) -> Result<(), NativeError> {
        match *self {}
    }
    fn map_anywhere(&self, _: VirtAddr, _: usize, _: PageFlags) -> Result<VirtRange, NativeError> {
        match *self {}
    }
    fn read(&self, _: VirtAddr, _: &mut [u8]) -> Result<(), NativeError> {
        match *self {}
    }
    fn check_writable(&self, _: VirtAddr, _: usize) -> Result<(), NativeError> {
        match *self {}
    }
    fn write(&self, _: VirtAddr, _: &[u8]) -> Result<(), NativeError> {
        match *self {}
    }
}

// SAFETY: uninhabited; there is no user execution to enter or leave.
unsafe impl UserContext for Infallible {
    type Space = Self;
    fn register(&self, _: RegisterId) -> Result<u64, NativeError> {
        match *self {}
    }
    fn set_register(&mut self, _: RegisterId, _: u64) -> Result<(), NativeError> {
        match *self {}
    }
    fn thread_pointer(&self) -> VirtAddr {
        match *self {}
    }
    fn set_thread_pointer(&mut self, _: VirtAddr) -> Result<(), NativeError> {
        match *self {}
    }
    fn resume(&mut self, _: &Self) -> Stop {
        match *self {}
    }
}
