use core::arch::global_asm;

use super::TaskContext;


global_asm!(include_str!("switch.S"));

extern "C" {
    pub fn __switch(current_tack_cx_ptr: *mut TaskContext, next_task_cx_ptr: *const TaskContext);
}
