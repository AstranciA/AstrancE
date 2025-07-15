use crate::SyscallResult;
use crate::ToLinuxResult;
use arceos_posix_api::ctypes;
use arceos_posix_api::{self as api};
use core::ffi::c_char;
use core::ffi::c_int;

#[cfg(feature = "fd")]
#[inline]
pub fn sys_close(fd: c_int) -> SyscallResult {
    api::sys_close(fd).to_linux_result()
}

#[cfg(feature = "fd")]
#[inline]
pub fn sys_dup(old_fd: c_int) -> SyscallResult {
    api::sys_dup(old_fd).to_linux_result()
}
#[cfg(feature = "fd")]
#[inline]
pub fn sys_dup2(old_fd: c_int, new_fd: c_int) -> SyscallResult {
    api::sys_dup2(old_fd, new_fd).to_linux_result()
}
#[cfg(feature = "fd")]
#[inline]
pub fn sys_fcntl(fd: c_int, cmd: c_int, arg: usize) -> SyscallResult {
    api::sys_fcntl(fd, cmd, arg).to_linux_result()
}

#[cfg(feature = "fd")]
#[inline]
pub fn sys_dup3(old_fd: c_int, new_fd: c_int) -> SyscallResult {
    api::sys_dup2(old_fd, new_fd).to_linux_result()
}

#[inline]
pub fn sys_ppoll(
    fds: *mut ctypes::pollfd,
    nfds: ctypes::nfds_t,
    // TODO: timeout_ts
    timeout_ts: *const ctypes::timespec,
    // TODO: sigmask
    sigmask: *const ctypes::sigset_t,
) -> SyscallResult {
    api::sys_ppoll(fds, nfds, timeout_ts, sigmask).to_linux_result()
}
