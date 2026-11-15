#![no_std]

//! Linux ABI policy for native execution. The platform owns execution and
//! memory; this crate never dereferences a guest address or selects a backend.
//! A caller exclusively owns a process while dispatching a syscall. No global
//! state or locks are required, and separate processes may run concurrently.

#[cfg(feature = "runtime")]
pub mod elf;
#[cfg(feature = "runtime")]
pub mod syscall;

#[cfg(feature = "runtime")]
pub mod stack;
