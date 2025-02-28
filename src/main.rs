#![feature(ascii_char)]
#![no_std]
#![no_main]

use core::arch::global_asm;

use sbi::{put_char, shutdown};

mod panic;
mod sbi;

global_asm!(include_str!("entry.asm"));

#[no_mangle]
pub fn rust_main() {
    run();
}

fn run() {
    for ch in "Hello, world!".chars() {
        put_char(ch.as_ascii().unwrap());
    }
    shutdown(false);
}
