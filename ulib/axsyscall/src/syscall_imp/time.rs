use core::error::Error;

use crate::{SyscallResult, ToLinuxResult};
use arceos_posix_api::{self as api, ctypes};
use axerrno::AxError;
use axmono::syscall::time;
use axmono::task::{ItimerConfig, get_itimer, set_itimer};
use linux_raw_sys::general::itimerval;

#[inline]
pub fn sys_clock_gettime(clk: ctypes::clockid_t, ts: *mut ctypes::timespec) -> SyscallResult {
    unsafe { api::sys_clock_gettime(clk, ts).to_linux_result() }
}

#[inline]
pub fn sys_nanosleep(req: *const ctypes::timespec, rem: *mut ctypes::timespec) -> SyscallResult {
    unsafe { api::sys_nanosleep(req, rem) }.to_linux_result()
}

#[inline]
pub fn sys_get_time_of_day(ts: *mut ctypes::timeval) -> SyscallResult {
    unsafe { api::sys_get_time_of_day(ts) }.to_linux_result()
}

#[inline]
pub fn sys_times(tms_ptr: usize) -> SyscallResult {
    axmono::syscall::time::sys_times(tms_ptr)
}

#[inline]
pub fn sys_setitimer(which: i32, new: *const itimerval, old: *mut itimerval) -> SyscallResult {
    time::sys_setitimer(which, new, old)
}

#[inline]
pub fn sys_getitimer(which: i32, curr: *mut itimerval) -> SyscallResult {
    time::sys_getitimer(which, curr)
}
