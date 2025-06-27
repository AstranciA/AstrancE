use crate::SyscallResult;
use arceos_posix_api::{self as api, ctypes};
use core::ffi::c_char;
use core::ffi::c_int;
use axlog::debug;

#[cfg(feature = "pipe")]
#[inline]
pub fn sys_pipe(fds: &mut [c_int]) -> SyscallResult {
    use crate::ToLinuxResult;
    debug!("pipe: fds = {:?}", fds);
    api::sys_pipe(fds).to_linux_result()
}
