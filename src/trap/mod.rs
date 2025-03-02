use core::arch::global_asm;

use context::TrapContext;
use riscv::{
    interrupt::supervisor::{Exception, Interrupt},
    register::{
        scause::{self, Trap},
        sie, stval,
        stvec::{self, Stvec},
    },
};

use crate::{
    debug,
    syscall::syscall,
    task::{exit_current_and_run_next, suspend_current_and_run_next},
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

enum Cause {
    Interrupt,
}
/// This function is called by __trap_entry in trap.S.
#[no_mangle]
pub fn trap_handler(cx: &mut TrapContext) -> &mut TrapContext {
    let scause = scause::read();
    let stval = stval::read();

    //debug!("trap: {:?}, stval: {:#x}", scause, stval);

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
