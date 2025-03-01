use riscv::register::sstatus::{self, Sstatus, SPP};

use crate::arch::{GPRegs, Reg};

#[repr(C)]
pub struct TrapContext {
    pub x: GPRegs, // but actually x1, sscratch, x3, unused, x5-x31
    pub sstatus: Sstatus,
    pub sepc: Reg,
}

impl TrapContext {
    pub fn set_sp(&mut self, sp: Reg) {
        self.x.set_sp(sp);
    }

    pub fn init_context(entry : usize, sp :Reg) -> Self {
        let mut sstatus = sstatus::read();
        sstatus.set_spp(SPP::User); // set supervisor mode
        let mut cx = Self {
            x : GPRegs::empty(),
            sstatus,
            sepc: entry as Reg,
        };
        cx.set_sp(sp);
        cx
    }
}
