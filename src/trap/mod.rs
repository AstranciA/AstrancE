use core::arch::global_asm;

use context::TrapContext;
use riscv::register::{
    scause::{self, Exception, Interrupt, Trap}, sie, sstatus, stval, stvec, utvec::TrapMode
};

use crate::{debug, syscall::syscall, task::{exit_current_and_run_next, suspend_current_and_run_next}, timer::set_next_trigger};

pub mod context;

global_asm!(include_str!("trap.S"));

pub fn init() {
    extern "C" {
        fn __trap_entry();
    }
    unsafe {
        stvec::write(__trap_entry as usize, TrapMode::Direct);
    }
}

pub fn enable_timer_interrupt() {
    unsafe { sie::set_stimer() };
    //unsafe { sstatus::clear_sie(); };
}

/// This function is called by __trap_entry in trap.S.
#[no_mangle]
pub fn trap_handler(cx: &mut TrapContext) -> &mut TrapContext {
    let scause = scause::read();
    let stval = stval::read();

    //debug!("trap: {:?}, stval: {:#x}", scause, stval);

    match scause.cause() {
        Trap::Exception(Exception::UserEnvCall) => {
            cx.sepc += 4;
            cx.x[10] = syscall(cx.x[17], [cx.x[10], cx.x[11], cx.x[12]]) as usize;
        }
        Trap::Exception(Exception::IllegalInstruction) => {
            kprintln!("IllegalInstruction in application, kernel killed it.");
            exit_current_and_run_next();
        }
        scause::Trap::Exception(Exception::StoreFault)
        | Trap::Exception(Exception::StorePageFault) => {
            kprintln!("PageFault in application, bad addr = {:#x}, bad instruction = {:#x}, kernel killed it.", stval, cx.sepc);
            exit_current_and_run_next();
        }
        Trap::Interrupt(Interrupt::SupervisorTimer) => {
            set_next_trigger();
            suspend_current_and_run_next();
        }
        _ => {
            panic!(
                "Unsupported trap: {:?}, stval: {:#x}",
                scause.cause(),
                stval
            )
        }
    }
    cx
}
