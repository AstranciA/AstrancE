use crate::{SyscallResult, ToLinuxResult};
use arceos_posix_api::ctypes::pid_t;
use arceos_posix_api::{self as api, ctypes};
use core::ffi::c_int;

pub fn sys_getrlimit(resource: c_int, rlimits: *mut ctypes::rlimit) -> SyscallResult {
    unsafe { api::sys_getrlimit(resource, rlimits).to_linux_result() }
}

pub fn sys_setrlimit(resource: c_int, rlimits: *mut ctypes::rlimit) -> SyscallResult {
    unsafe { api::sys_setrlimit(resource, rlimits).to_linux_result() }
}

pub fn sys_prlimit64(
    pid: pid_t,
    resource: c_int,
    new_limit: *mut ctypes::rlimit,
    old_limit: *mut ctypes::rlimit,
) -> SyscallResult {
    unsafe { api::sys_prlimit64(pid, resource, new_limit, old_limit).to_linux_result() }
}
