#[cfg(feature = "fast-trap")]
use fast_trap::{FastContext, FastResult};
use page_table_entry::MappingFlags;
use riscv::interrupt::Trap;
use riscv::interrupt::supervisor::{Exception as E, Interrupt as I};
use riscv::register::{mepc, scause, sstatus, stval};

use crate::arch::{ITrapFrame, TrapFrame};
use crate::trap::{post_trap, pre_trap};

#[cfg(not(feature = "fast-trap"))]
core::arch::global_asm!(
    include_asm_macros!(),
    include_str!("trap.S"),
    trapframe_size = const core::mem::size_of::<TrapFrame>(),
);

fn handle_breakpoint(sepc: &mut usize) {
    debug!("Exception(Breakpoint) @ {:#x} ", sepc);
    *sepc += 2
}

fn handle_page_fault(tf: &TrapFrame, mut access_flags: MappingFlags, is_user: bool) {
    if is_user {
        access_flags |= MappingFlags::USER;
    }
    let vaddr = va!(stval::read());
    if !handle_trap!(PAGE_FAULT, vaddr, access_flags, is_user) {
        panic!(
            "Unhandled {} Page Fault @ {:#x}, fault_vaddr={:#x} ({:?}):\n{:#x?}",
            if is_user { "User" } else { "Supervisor" },
            tf.get_ip(),
            vaddr,
            access_flags,
            tf,
        );
    }
    debug!("page fault handled");
}

#[unsafe(no_mangle)]
#[cfg(not(feature = "fast-trap"))]
fn riscv_trap_handler(tf: &mut TrapFrame, from_user: bool) {
    use riscv::register::sscratch;

    let scause = scause::read();
    pre_trap(tf);
    if let Ok(cause) = scause.cause().try_into::<I, E>() {
        match cause {
            #[cfg(feature = "uspace")]
            Trap::Exception(E::UserEnvCall) => {
                tf.set_retval(crate::trap::handle_syscall(tf, tf.regs.a7) as usize);
                tf.step_ip();
            }
            Trap::Exception(E::LoadPageFault) => {
                handle_page_fault(tf, MappingFlags::READ, from_user)
            }
            Trap::Exception(E::StorePageFault) => {
                handle_page_fault(tf, MappingFlags::WRITE, from_user)
            }
            Trap::Exception(E::InstructionPageFault) => {
                handle_page_fault(tf, MappingFlags::EXECUTE, from_user)
            }
            Trap::Exception(E::Breakpoint) => handle_breakpoint(&mut tf.get_ip()),
            Trap::Interrupt(_) => {
                handle_trap!(IRQ, scause.bits());
            }
            _ => {
                panic!(
                    "Unhandled trap {:?} @ {:#x}:\n{:#x?}",
                    cause,
                    tf.get_ip(),
                    tf
                );
            }
        }
    } else {
        panic!(
            "Unknown trap {:?} @ {:#x}:\n{:#x?}",
            scause.cause(),
            tf.get_ip(),
            tf
        );
    }
    post_trap(tf);
}

pub mod fast_trap_cause {
    pub const BOOT: usize = 24;
    pub const CALL: usize = 25;
}

#[cfg(feature = "fast-trap")]
pub extern "C" fn riscv_fast_handler(
    mut ctx: FastContext,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
    a7: usize,
) -> FastResult {
    // WARN: log is not avaiable here since gp is not set yet
    use riscv::register::{
        sepc, sscratch,
        sstatus::{self, SPP},
    };
    unsafe { sstatus::clear_sie() };
    let scause = scause::read();
    // FIXME:
    let from_user = true;
    let a0 = ctx.a0();
    let tf = ctx.regs();
    if let Ok(cause) = scause.cause().try_into::<I, E>() {
        //pre_trap(tf);
        match cause {
            #[cfg(feature = "uspace")]
            Trap::Exception(E::UserEnvCall) => {
                // WARN: no a6
                let args = [a0, a1, a2, a3, a4, a5];
                tf.set_retval(crate::trap::handle_syscall(&args, a7) as usize);
                // FIXME: tf.step_ip();
                //tf.step_ip();
            }
            Trap::Exception(E::LoadPageFault) => {
                handle_page_fault(tf, MappingFlags::READ, from_user)
            }
            Trap::Exception(E::StorePageFault) => {
                handle_page_fault(tf, MappingFlags::WRITE, from_user)
            }
            Trap::Exception(E::InstructionPageFault) => {
                handle_page_fault(tf, MappingFlags::EXECUTE, from_user)
            }
            Trap::Exception(E::Breakpoint) => handle_breakpoint(&mut tf.get_ip()),
            Trap::Interrupt(_) => {
                handle_trap!(IRQ, scause.bits());
            }
            _ => {
                panic!(
                    "Unhandled trap {:?} @ {:#x}:\n{:#x?}",
                    cause,
                    tf.get_ip(),
                    tf
                );
            }
        }
        //post_trap(tf);
        let sepc = sepc::read();
        sepc::write(sepc + 4);
        ctx.restore()
    } else {
        if let Trap::Exception(code) = scause.cause() {
            match code {
                //fast_trap_cause::BOOT => sepc::write(tf.get_ip()),
                fast_trap_cause::BOOT => warn!("boot fast-trap"),
                fast_trap_cause::CALL => log::warn!("call fast-trap inline!"),
                _ => panic!(
                    "Unknown trap {:?} @ {:#x}:\n{:#x?}",
                    scause.cause(),
                    tf.get_ip(),
                    tf
                ),
            }
            // FIXME: 将spp作为tf字段传过来
            unsafe { sstatus::set_spp(SPP::User) };
            //ctx.regs().a = [ctx.a0(), a1, a2, a3, a4, a5, a6, a7];
            unsafe {
                core::arch::asm!(
                    "
                csrw sscratch, {sp}
                csrw     sepc, {pc}
            ",
                    sp = in(reg) tf.sp,
                    pc = in(reg) tf.pc,
                );
            }
            return ctx.restore();
        }
        panic!(
            "Unknown trap {:?} @ {:#x}:\n{:#x?}",
            scause.cause(),
            tf.get_ip(),
            tf
        );
    }
}

#[cfg(feature = "fast-trap")]
pub extern "C" fn riscv_entire_handler(
    mut ctx: fast_trap::EntireContext,
) -> fast_trap::EntireResult {
    use fast_trap::ContextExt;
    use riscv::register::{
        sepc, sscratch,
        sstatus::{self, SPP},
    };
    unsafe { sstatus::clear_sie() };
    let (mut ctx, mail) = ctx.split();
    let scause = scause::read();
    // FIXME:
    let from_user = true;
    let tf = ctx.regs();
    let sepc = sepc::read();
    if let Ok(cause) = scause.cause().try_into::<I, E>() {
        //pre_trap(tf);
        match cause {
            #[cfg(feature = "uspace")]
            Trap::Exception(E::UserEnvCall) => {
                // WARN: no a6
                let args = [tf.a[0], tf.a[1], tf.a[2], tf.a[3], tf.a[4], tf.a[5]];
                tf.set_retval(crate::trap::handle_syscall(&args, tf.a[7]) as usize);
                // FIXME: tf.step_ip();
                //tf.step_ip();
            }
            Trap::Exception(E::LoadPageFault) => {
                handle_page_fault(tf, MappingFlags::READ, from_user)
            }
            Trap::Exception(E::StorePageFault) => {
                handle_page_fault(tf, MappingFlags::WRITE, from_user)
            }
            Trap::Exception(E::InstructionPageFault) => {
                handle_page_fault(tf, MappingFlags::EXECUTE, from_user)
            }
            Trap::Exception(E::Breakpoint) => handle_breakpoint(&mut tf.get_ip()),
            Trap::Interrupt(_) => {
                handle_trap!(IRQ, scause.bits());
            }
            _ => {
                panic!(
                    "Unhandled trap {:?} @ {:#x}:\n{:#x?}",
                    cause,
                    tf.get_ip(),
                    tf
                );
            }
        }
        //post_trap(tf);
        sepc::write(sepc + 4);
        let sepc = sepc::read();
        ctx.restore()
    } else {
        if let Trap::Exception(code) = scause.cause() {
            match code {
                //fast_trap_cause::BOOT => sepc::write(tf.get_ip()),
                fast_trap_cause::BOOT => debug!("boot fast-trap"),
                fast_trap_cause::CALL => debug!("call fast-trap inline!"),
                _ => panic!(
                    "Unknown trap {:?} @ {:#x}:\n{:#x?}",
                    scause.cause(),
                    tf.get_ip(),
                    tf
                ),
            }
            // FIXME: 将spp作为tf字段传过来
            unsafe { sstatus::set_spp(SPP::User) };
            //ctx.regs().a = [ctx.a0(), a1, a2, a3, a4, a5, a6, a7];
            unsafe {
                core::arch::asm!(
                    "
                csrw sscratch, {sp}
                csrw     sepc, {pc}
            ",
                    sp = in(reg) tf.sp,
                    pc = in(reg) tf.pc,
                );
            }
            return ctx.restore();
        }
        panic!(
            "Unknown trap {:?} @ {:#x}:\n{:#x?}",
            scause.cause(),
            tf.get_ip(),
            tf
        );
    }
}
