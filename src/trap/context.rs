use riscv::register::{
    satp::Satp,
    sstatus::{self, Sstatus, SPP},
};

use crate::arch::{GPRegs, Reg};

#[derive(Debug)]
#[repr(C)]
pub struct TrapContext {
    pub x: GPRegs, // but actually x1, sscratch, x3, unused, x5-x31
    pub sstatus: Sstatus,
    pub sepc: Reg,
    pub kernel_satp: usize,
    pub kernel_sp: usize,
    pub trap_handler: usize, // Addr of trap_handler
}

impl TrapContext {
    pub fn set_sp(&mut self, sp: Reg) {
        self.x.set_sp(sp);
    }

    pub fn app_init_context(
        entry: usize,
        sp: Reg,
        kernel_satp: Satp,
        kernel_sp: Reg,
        trap_handler: usize,
    ) -> Self {
        let mut sstatus = sstatus::read();
        sstatus.set_spp(SPP::User); // set supervisor mode
        //kprintln!("trap_handler: {:x}", trap_handler as usize);
        let mut cx = Self {
            x: GPRegs::empty(),
            sstatus,
            sepc: entry as Reg,
            kernel_satp: kernel_satp.bits(),
            kernel_sp,
            trap_handler,
        };
        cx.set_sp(sp);
        //kprintln!("cx: {:?}", cx);
        cx
    }
}
