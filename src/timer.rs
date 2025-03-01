use crate::{board::CLOCK_FREQ, config::KERNEL_HEAP_SIZE, sbi::set_timer};
use riscv::register::time;

const TICKS_PER_SEC: usize = 100;
const MSEC_PRE_SEC: usize = 1000;

pub fn get_time() -> usize {
    time::read()
}

pub fn get_time_ms() -> usize {
    get_time() / (CLOCK_FREQ / MSEC_PRE_SEC)
}

pub fn set_next_trigger() {
    set_timer(get_time() + CLOCK_FREQ / TICKS_PER_SEC);
}
