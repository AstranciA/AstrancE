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
        warn!("{:?}", cause);
        match cause {
            #[cfg(feature = "uspace")]
            Trap::Exception(E::UserEnvCall) => {
                tf.set_retval(crate::trap::handle_syscall(
                    &[
                        tf.regs.a0, tf.regs.a1, tf.regs.a2, tf.regs.a3, tf.regs.a4, tf.regs.a5,
                    ],
                    tf.regs.a7,
                ) as usize);
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
    debug!("tf: {:#x?}", tf);
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
    use core::arch::asm;

    use riscv::register::sstatus::{self, SPP};
    unsafe { asm!("fence iorw, iorw"); }
    unsafe { sstatus::clear_sie() };
    let scause = scause::read();
    // FIXME:: monokernel and unikernel "user" is in different mode;
    let a0 = ctx.a0();
    let tf = ctx.regs();
    if let Ok(_) = scause.cause().try_into::<I, E>() {
        pre_trap(tf);
        tf.a = [a0, a1, a2, a3, a4, a5, a6, a7];
        return ctx.continue_with(riscv_entire_handler, [a0, a1, a2, a3, a4, a5, a6, a7]);
    } else {
        if let Trap::Exception(code) = scause.cause() {
            match code {
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
            warn!("init uspace trap, tf: {tf:#x?}");
            tf.t = [0; 7];
            tf.s = [0; 12];
            tf.tp = 0;
            tf.gp = 0;
            //ctx.regs().a = [ctx.a0(), a1, a2, a3, a4, a5, a6, a7];
            unsafe {
                core::arch::asm!(
                    "
                csrw sscratch, {sp}
                csrw     sepc, {pc}
                mv   ra, {ra}
            ",
                    sp = in(reg) tf.sp,
                    pc = in(reg) tf.pc,
                    ra = in(reg) tf.ra,
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
#[allow(static_mut_refs)]
pub extern "C" fn riscv_entire_handler(
    mut ctx: fast_trap::EntireContext<[usize; 8]>,
) -> fast_trap::EntireResult {
    use core::ptr::NonNull;

    use fast_trap::{ContextExt, FlowContext, FreeTrapStack};
    use riscv::register::{
        sepc,
        sstatus::{self, SPP},
    };
    // FIXME:: monokernel and unikernel "user" is in different mode;
    let from_user = sstatus::read().spp() == SPP::User;
    let scause = scause::read();
    let (mut ctx, args) = ctx.split();
    let tf = ctx.regs();

    static mut ROOT_STACK: [u8; 4096] = [0; 4096];
    static mut ROOT_CONTEXT: FlowContext = FlowContext::ZERO;

    if let Ok(cause) = scause.cause().try_into::<I, E>() {
        let sepc = sepc::read();
        tf.set_ip(sepc);

        pre_trap(tf);
        warn!("spp: {:?}", sstatus::read().spp());
        match cause {
            #[cfg(feature = "uspace")]
            Trap::Exception(E::UserEnvCall) => {
                if !from_user {
                    panic!("user mode syscall from kernel mode");
                }
                // 保护栈，用于嵌套陷入
                let stack = unsafe { ROOT_STACK.as_ptr_range() };
                let context_ptr = unsafe { NonNull::new_unchecked(&raw mut ROOT_CONTEXT) };
                let _protect = FreeTrapStack::new(
                    unsafe { stack.start as usize..stack.end as usize },
                    |_| {},
                    context_ptr,
                    riscv_fast_handler,
                    ContextExt::read(),
                )
                .unwrap();
                let _loaded = _protect.load();
                // WARN: no a6
                tf.set_retval(crate::trap::handle_syscall(
                    &[args[0], args[1], args[2], args[3], args[4], args[5]],
                    args[7],
                ) as usize);
                _loaded.unload();
                tf.step_ip();
            }
            Trap::Exception(E::LoadPageFault) => {
                handle_page_fault(tf, MappingFlags::READ, from_user)
            }
            Trap::Exception(E::StorePageFault) => {
                warn!("store page fault from {:x}", sepc::read());
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
        sepc::write(tf.get_ip());
        post_trap(tf);
        debug!("after trap, tf: {tf:#x?}");
        ctx.restore()
    } else {
        if let Trap::Exception(code) = scause.cause() {
            match code {
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
