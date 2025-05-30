#![cfg_attr(feature = "axstd", no_std)]
#![cfg_attr(feature = "axstd", no_main)]

#[cfg(feature = "axstd")]
use axstd::println;
use axsyscall::basic_syscall_handler;

const s: &str = "Hello, axsyscall!";
const sps: &str = "Hello, AstrancE\n";
#[cfg_attr(feature = "axstd", unsafe(no_mangle))]
fn main() {
    println!("Hello, world!");
    let o = basic_syscall_handler(64, [1, sps.as_ptr() as usize, s.len(), 0, 0, 0]);
}
