use core::ascii;

use sbi_rt::*;

pub fn put_char(c: ascii::Char) -> SbiRet{
    sbi_rt::console_write_byte(c.to_u8())
}

pub fn shutdown(failure: bool) -> ! {
    if !failure {
        system_reset(Shutdown, NoReason);
    } else {
        system_reset(Shutdown, SystemFailure);
    }
    unreachable!();
}
