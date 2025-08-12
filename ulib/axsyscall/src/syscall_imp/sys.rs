use core::ffi::{c_uint, c_void};
use axerrno::LinuxResult;
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

#[inline]
pub unsafe fn sys_getrandom(
    buf: *mut c_void,
    buflen: usize,
    flags: c_uint
) -> SyscallResult {
    arceos_posix_api::sys_getrandom(buf as *mut c_void, buflen, flags).to_linux_result()
}