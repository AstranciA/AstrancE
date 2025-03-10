#![feature(ascii_char)]
#![feature(associated_type_defaults)]
#![feature(alloc_error_handler)]
#![feature(new_range_api)]
#![feature(step_trait)]
#![no_std]
#![no_main]

#[macro_use]
extern crate bitflags;
extern crate alloc;
#[macro_use]
extern crate lazy_static;

use core::arch::{asm, global_asm};

mod config;

#[macro_use]
mod console;
mod sync;

use aelog::Level;
#[macro_use]
use aelog::{AELogger, Appender};
use mm::{
    address::{PhysAddr, VirtAddr, VirtPageNum},
    frame_allocator, heap_allocator,
    memory_set::KERNEL_SPACE,
};
use sbi::{put_str, shutdown};

mod board;
mod panic;
mod sbi;
mod stack_trace;
mod timer;

mod arch;
mod loader;
mod mm;
mod syscall;
mod task;
mod trap;

global_asm!(include_str!("entry.asm"));
global_asm!(include_str!("link_app.S"));

#[no_mangle]
pub fn rust_main() {
    init();
}

struct ConsoleAppender;
impl Appender for ConsoleAppender {
    fn write(&self, _: &aelog::Record, formatted: alloc::string::String) {
        put_str(formatted.as_str());
    }
}
lazy_static! {
    pub static ref LOGGER: AELogger<'static> = {
        let mut logger = AELogger::default();
        logger.add_appender(ConsoleAppender);
        logger
    };
}

fn init() {
    clear_bss();
    print_basic_info();

    init_mm();

    aelog::init(&LOGGER).unwrap();
    aelog::info!("AstrancaOS starting...");
    aelog::info!("{}", include_str!("assets/logo2.txt"));
    task::print_tasks_info();

    trap::init();
    trap::enable_timer_interrupt();
    timer::set_next_trigger();

    task::run_first_task();
    shutdown(false);
}
fn init_mm() {
    heap_allocator::init_heap();
    frame_allocator::init_frame_allocator();
    KERNEL_SPACE.exclusive_access().activate();
    remap_test();
}

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
fn print_basic_info() {
    fn print_section_info(name: &str, start: usize, end: usize) {
        aelog::info!("{:8}: [{:#x}, {:#x})", name, start, end);
    }
    print_section_info(".text", stext as usize, etext as usize);
    print_section_info(".rodata", srodata as usize, erodata as usize);
    print_section_info(".data", sdata as usize, edata as usize);
    print_section_info(".stack", sstack as usize, estack as usize);
    print_section_info(".bss", sbss as usize, ebss as usize);
}
pub fn remap_test() {
    let kernel_space = KERNEL_SPACE.exclusive_access();
    let mid_text: VirtAddr = ((stext as usize + etext as usize) / 2).into();
    let mid_rodata: VirtAddr = ((srodata as usize + erodata as usize) / 2).into();
    let mid_data: VirtAddr = ((sdata as usize + edata as usize) / 2).into();
    assert!(!kernel_space
        .page_table
        .translate(mid_text.floor())
        .unwrap()
        .is_writable(),);
    assert!(!kernel_space
        .page_table
        .translate(mid_rodata.floor())
        .unwrap()
        .is_writable(),);
    assert!(!kernel_space
        .page_table
        .translate(mid_data.floor())
        .unwrap()
        .is_executable(),);
    //for ro_addr in stext as usize..etext as usize {
    /*
     *println!("{:x}", ro_addr);
     *println!("{:x}", VirtPageNum(ro_addr).0);
     */
    //let ppn2 = kernel_space
    //.page_table
    //.translate(VirtAddr(ro_addr).floor())
    //.unwrap()
    //.ppn();

    //let pa2 = PhysAddr::from(ppn2).0 | (ro_addr & 0xfff);
    //let pa = ro_addr;
    ////println!("pa2:0x{:x}, pa:0x{:x}", pa2, pa);
    //assert_eq!(pa2, pa);
    //}
    /*
     *for v in kernel_space.page_table.frames.iter() {
     *    warn!("{:?}",v.ppn);
     *}
     */
}
fn clear_bss() {
    extern "C" {
        fn sbss();
        fn ebss();
    }
    unsafe {
        core::slice::from_raw_parts_mut(sbss as usize as *mut u8, ebss as usize - sbss as usize)
            .fill(0)
    };
}
