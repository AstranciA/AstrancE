use core::{any::Any, arch::{asm, global_asm}};

use riscv::{
    interrupt::supervisor::{Exception, Interrupt},
    register::{
        scause::{self, Trap},
        sie, stval,
        stvec::{self, Stvec, TrapMode},
    },
};

use crate::{
    config::{TRAMPOLINE, TRAP_CONTEXT},
    debug,
    mm::page_table::PageTable,
    syscall::syscall,
    task::{
        current_trap_cx, current_user_token, exit_current_and_run_next,
        suspend_current_and_run_next,
    },
    timer::set_next_trigger,
};

pub mod context;

global_asm!(include_str!("trap.S"));

pub fn init() {
    extern "C" {
        fn __trap_entry();
    }
    let mut stvec_target = Stvec::from_bits(__trap_entry as usize);
    stvec_target.set_trap_mode(stvec::TrapMode::Direct);
    unsafe {
        stvec::write(stvec_target);
    }
}

pub fn enable_timer_interrupt() {
    unsafe { sie::set_stimer() };
    //unsafe { sstatus::clear_sie(); };
}

fn set_kernel_trap_entry() {
    let mut kstvec: Stvec = Stvec::from_bits(trap_from_kernel as usize);
    kstvec.set_trap_mode(TrapMode::Direct);
    unsafe {
        stvec::write(kstvec);
    }
}

fn set_user_trap_entry() {
    let mut ustvec: Stvec = Stvec::from_bits(TRAMPOLINE);
    ustvec.set_trap_mode(TrapMode::Direct);
    unsafe {
        stvec::write(ustvec);
    }
}

#[no_mangle]
pub fn trap_return() -> ! {
    set_user_trap_entry();
    let trap_cx_ptr = TRAP_CONTEXT;
    let user_satp = current_user_token();
    extern "C" {
        fn __trap_entry();
        fn __restore();
    }

    // va of __restore in user space is as same as in kernel space
    let restore_va = __restore as usize - __trap_entry as usize + TRAMPOLINE;

    unsafe {
        asm!(
            "fence.i",
            "jr {restore_va}",
            restore_va = in(reg) restore_va,
            in("a0") trap_cx_ptr,
            in("a1") user_satp.bits(),
            options(noreturn)
        );
    }
}

#[no_mangle]
pub fn trap_from_kernel() -> ! {
    panic!("a trap from kernel!");
}

/// This function is called by __trap_entry in trap.S.
#[no_mangle]
pub fn trap_handler() -> ! {
    set_kernel_trap_entry();
    let cx = current_trap_cx();
    let scause = scause::read();
    let stval = stval::read();

    //warn!("trap: {:?}, stval: {:#x}", scause, stval);

    let raw_trap = scause.cause();
    let standart_trap: Trap<Interrupt, Exception> = raw_trap.try_into().unwrap();

    match standart_trap {
        Trap::Exception(Exception::UserEnvCall) => {
            cx.sepc += 4;
            cx.x[10] = syscall(cx.x[17], [cx.x[10], cx.x[11], cx.x[12]]) as usize;
        }
        Trap::Exception(Exception::IllegalInstruction) => {
            kprintln!("IllegalInstruction in application, kernel killed it.");
            exit_current_and_run_next();
        }
        Trap::Exception(Exception::StoreFault)
        | Trap::Exception(Exception::LoadPageFault)
        | Trap::Exception(Exception::StorePageFault) => {
            warn!("PageFault in application ({:?}), bad addr = {:#x}, bad instruction = {:#x}, kernel killed it.", standart_trap, stval, cx.sepc);
            exit_current_and_run_next();
        }
        Trap::Interrupt(Interrupt::SupervisorTimer) => {
            set_next_trigger();
            suspend_current_and_run_next();
        }
        _ => {
            panic!(
                "Unsupported trap ({:?}): scause:{:?}, stval: {:#x}",
                standart_trap,
                scause.cause(),
                stval
            )
        }
    }
    trap_return();
}
