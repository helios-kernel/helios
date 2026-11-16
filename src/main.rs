#![no_std]
#![cfg_attr(target_os = "none", no_main)]

extern crate alloc;

#[cfg(not(target_os = "none"))]
fn main() {
    helios_hosted::main();
}

// otherwise, the entry point is defined by the active bare-metal platform crate.

#[cfg(target_arch = "aarch64")]
use helios_aarch64 as _;
#[cfg(target_arch = "riscv64")]
use helios_riscv as _;
#[cfg(target_arch = "x86_64")]
use helios_x86 as _;

#[cfg(all(
    feature = "linux-prototype",
    not(all(target_arch = "x86_64", target_os = "none"))
))]
compile_error!("linux-prototype requires x86_64-unknown-none");

#[cfg(all(
    feature = "linux-prototype",
    target_arch = "x86_64",
    target_os = "none"
))]
mod linux;

#[cfg(all(
    feature = "linux-prototype",
    target_arch = "x86_64",
    target_os = "none"
))]
#[unsafe(no_mangle)]
#[unsafe(naked)]
extern "C" fn _start() -> ! {
    core::arch::naked_asm!("jmp {start}", start = sym helios_x86::start::<linux::Prototype>);
}
