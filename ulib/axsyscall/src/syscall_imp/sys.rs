use arceos_posix_api::UtsName;
use axtask::current;

use crate::{SyscallResult, ToLinuxResult};

#[inline]
pub fn sys_uname(buf: *mut u8) -> SyscallResult {
    arceos_posix_api::sys_uname(buf as *mut UtsName).to_linux_result()
}
