use arceos_posix_api::{UtsName, SysInfo};
use axtask::current;

use crate::{SyscallResult, ToLinuxResult};

#[inline]
pub fn sys_uname(buf: *mut u8) -> SyscallResult {
    arceos_posix_api::sys_uname(buf as *mut UtsName).to_linux_result()
}

#[inline]
pub fn sys_sysinfo(buf: *mut SysInfo) -> SyscallResult {
    arceos_posix_api::sys_sysinfo(buf as *mut SysInfo).to_linux_result()
}
