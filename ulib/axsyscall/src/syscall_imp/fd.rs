use crate::SyscallResult;
use crate::ToLinuxResult;
use arceos_posix_api::ctypes;
use arceos_posix_api::{self as api};
use core::ffi::c_char;
use core::ffi::c_int;
use crate::ctypes::off_t;
use crate::ctypes::size_t;

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

#[cfg(feature = "fd")]
#[inline]
pub fn sys_copy_file_range(
    fd_in: c_int,
    off_in: *mut off_t,
    fd_out: c_int,
    off_out: *mut off_t,
    size: size_t, flags: u32,
) -> SyscallResult {
    api::sys_copy_file_range(fd_in, off_in, fd_out, off_out, size, flags)
}

#[cfg(feature = "fd")]
#[inline]
pub fn sys_splice(
    fd_in: c_int,
    off_in: *mut off_t,
    fd_out: c_int,
    off_out: *mut off_t,
    size: size_t,
    flags: u32,
) -> SyscallResult {
    let off_in_opt: Option<*mut i64> = if off_in.is_null() {
        None
    } else {
        Some(off_in)
    };

    let off_out_opt: Option<*mut i64> = if off_out.is_null() {
        None
    } else {
        Some(off_out)
    };
    api::splice(fd_in, off_in_opt, fd_out, off_out_opt, size, flags)
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
