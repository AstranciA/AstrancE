//! Constants used in AstrancE.
use crate::console::LogLevel;

pub static LOG_LEVEL: LogLevel = LogLevel::DEFAULT;

pub const USER_STACK_SIZE: usize = 4096 * 2;
pub const KERNEL_STACK_SIZE: usize = 4096 * 2;
pub const KERNEL_HEAP_SIZE: usize = 0x30_0000;

pub const PAGE_SIZE: usize = 0x1000;
pub const TRAMPOLINE: usize = usize::MAX - PAGE_SIZE + 1;
pub const TRAP_CONTEXT: usize = TRAMPOLINE - PAGE_SIZE;
pub const MEMORY_END: usize = 0x88800000;

pub fn kernel_stack_position(app_id: usize) -> (usize, usize) {
    let top = TRAMPOLINE - app_id * (KERNEL_STACK_SIZE + PAGE_SIZE);
    let bottom = top - KERNEL_STACK_SIZE;
    (bottom, top)
}

/*
#[cfg(feature = "board_k210")]
pub const CLOCK_FREQ: usize = 403000000 / 62;

#[cfg(feature = "board_qemu")]
pub const CLOCK_FREQ: usize = 12500000;
*/
pub use crate::board::CLOCK_FREQ;
