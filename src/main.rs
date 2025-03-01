#![feature(ascii_char)]
#![feature(associated_type_defaults)]
#![no_std]
#![no_main]

use core::arch::{asm, global_asm};

mod config;

#[macro_use]
mod console;
mod sync;

use sbi::shutdown;

mod panic;
mod sbi;
mod timer;
mod board;

mod arch;
mod syscall;
mod trap;
mod task;
mod loader;

global_asm!(include_str!("entry.asm"));
global_asm!(include_str!("link_app.S"));

#[no_mangle]
pub fn rust_main() {
    init();
}

fn init() {
    clear_bss();
    print_basic_info();
    trap::init();
    loader::load_apps();
    task::print_tasks_info();

    trap::enable_timer_interrupt();
    timer::set_next_trigger();

    task::run_first_task();
    shutdown(false);
}
fn print_basic_info() {
    extern "C" {
        fn stext();
        fn etext();
        fn srodata();
        fn erodata();
        fn sdata();
        fn edata();
        fn sstack();
        fn estack();
        fn sbss();
        fn ebss();
    }
    fn print_section_info(name: &str, start: usize, end: usize) {
        kprintln!("{:8}: [{:#x}, {:#x})", name, start, end);
    }
    print_section_info(".text", stext as usize, etext as usize);
    print_section_info(".rodata", srodata as usize, erodata as usize);
    print_section_info(".data", sdata as usize, edata as usize);
    print_section_info(".stack", sstack as usize, estack as usize);
    print_section_info(".bss", sbss as usize, ebss as usize);
}
fn clear_bss() {
    extern "C" {
        fn sbss();
        fn ebss();
    }
    (sbss as usize..ebss as usize).for_each(|a| unsafe { (a as *mut u8).write_volatile(0) });
}
