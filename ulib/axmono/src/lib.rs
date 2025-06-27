/*!
AstrancE lib for building a monolithic kernel
This library mainly provides a set of functions for userspace applications to interact with the kernel.
Although AstrancE is designed to be a unikernel, some may want to use user mode codes.
*/
#![no_std]
#![feature(never_type)]
#![feature(stmt_expr_attributes)]
#![feature(naked_functions)]
#[macro_use]
extern crate alloc;
#[macro_use]
extern crate axlog;

// extern crate axsyscall;
pub mod ctypes;
pub mod ptr;
pub mod utils;
pub mod fs;

mod dynamic;
use core::clone;

use axerrno::AxResult;
use axhal::arch::TrapFrame;
use axhal::trap::{SYSCALL, register_trap_handler};
use axmm::kernel_aspace;
use axprocess::Process;
use axtask::{current, yield_now};
use ctypes::{CloneFlags, WaitStatus};
use task::sys_waitpid;

pub mod elf;
pub mod loader;
#[cfg(feature = "syscalls")]
pub mod syscall;

#[cfg(feature = "process")]
pub mod task;
#[cfg(feature = "process")]
pub use task::init_proc;

#[cfg(feature = "mm")]
pub mod mm;

#[cfg(any(feature = "mm", feature = "process"))]
/// If the target architecture requires it, the kernel portion of the address
/// space will be copied to the user address space.
pub fn copy_from_kernel(aspace: &mut axmm::AddrSpace) -> AxResult {
    use axmm::kernel_aspace;

    if !cfg!(target_arch = "aarch64") && !cfg!(target_arch = "loongarch64") {
        // ARMv8 (aarch64) and LoongArch64 use separate page tables for user space
        // (aarch64: TTBR0_EL1, LoongArch64: PGDL), so there is no need to copy the
        // kernel portion to the user page table.
        aspace.copy_mappings_from(&kernel_aspace().lock(), false)?;
    }

    Ok(())
}


pub fn init() {
    let curr = current();
    Process::new_init(curr.id().as_u64().try_into().unwrap()).build();
}
