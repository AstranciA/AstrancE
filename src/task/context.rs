use crate::{arch::{Reg, SavedRegs}, trap::trap_return};

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct TaskContext {
    pub ra: Reg,
    pub sp: Reg,
    s: SavedRegs, // WARN: riscv saved regs
}

impl TaskContext {
    pub fn zero_init() -> Self {
        Self {
            ra: 0,
            sp: 0,
            s: SavedRegs::empty(),
        }
    }

    pub fn prepare_restore(kstack_ptr: *const usize) -> Self {
        extern "C" {
            fn __restore();
        }
        Self {
            ra: trap_return as Reg,
            sp: kstack_ptr as Reg,
            s: SavedRegs::empty(),
        }
    }
}
