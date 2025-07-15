use crate::SyscallResult;
use crate::ToLinuxResult;
use arceos_posix_api::{self as api, ctypes};
use core::ffi::c_char;
use core::ffi::c_int;
use core::ffi::c_void;

#[inline]
pub fn sys_read(fd: usize, buf: &mut [u8]) -> SyscallResult {
    api::sys_read(fd as i32, buf.as_mut_ptr() as *mut c_void, buf.len()).to_linux_result()
}

pub fn sys_readv(fd: c_int, iov: *const ctypes::iovec, iocnt: c_int) -> SyscallResult {
    unsafe { api::sys_readv(fd, iov, iocnt).to_linux_result() }
}

#[inline]
pub fn sys_write(fd: usize, buf: &[u8]) -> SyscallResult {
    api::sys_write(fd as i32, buf.as_ptr() as *mut c_void, buf.len()).to_linux_result()
}

#[inline]
pub fn sys_writev(fd: c_int, iov: *const ctypes::iovec, iocnt: c_int) -> SyscallResult {
    unsafe { api::sys_writev(fd, iov, iocnt) }.to_linux_result()
}

#[inline]
pub fn sys_pselect(
    nfds: c_int,
    readfds: *mut ctypes::fd_set,
    writefds: *mut ctypes::fd_set,
    exceptfds: *mut ctypes::fd_set,
    timeout: *const ctypes::timespec,
    sigmask: *const i64,
) -> SyscallResult{
    unsafe { axmono::syscall::io::sys_pselect(nfds, readfds, writefds, exceptfds, timeout, sigmask as *const _)}
}
