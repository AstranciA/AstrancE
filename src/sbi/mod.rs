use core::{ascii};

use sbi_rt::*;

pub fn put_ascii(c: ascii::Char) -> SbiRet {
    sbi_rt::console_write_byte(c.to_u8())
}
pub fn put_str(c: &str) -> SbiRet {
    let bytes = c.as_bytes();
    let bytes_range = bytes.as_ptr_range();
    let data = Physical::new(
        c.len(),
        bytes_range.start as usize,
        bytes_range.end as usize,
    );
    sbi_rt::console_write(data)
}

pub fn shutdown(failure: bool) -> ! {
    if !failure {
        system_reset(Shutdown, NoReason);
    } else {
        system_reset(Shutdown, SystemFailure);
    }
    unreachable!();
}

pub fn set_timer(timer: usize) -> SbiRet {
    sbi_rt::set_timer(timer as _)
}
