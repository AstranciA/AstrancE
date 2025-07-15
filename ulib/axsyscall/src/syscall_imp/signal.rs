use crate::SyscallResult;
use crate::ToLinuxResult;

#[inline]
pub fn sys_rt_sigaction(signum: i32, act: usize, oldact: usize) -> SyscallResult {
    axmono::syscall::signal::sys_rt_sigaction(signum, act, oldact)
}

#[inline]
pub fn sys_rt_sigprocmask(how: i32, set: usize, oldset: usize) -> SyscallResult {
    axmono::syscall::signal::sys_rt_sigprocmask(how, set, oldset)
}

#[inline]
pub fn sys_rt_sigtimedwait(set: usize, info: usize, timeout: usize) -> SyscallResult {
    axmono::syscall::signal::sys_rt_sigtimedwait(set, info, timeout)
}

#[inline]
pub fn sys_rt_sigreturn() -> SyscallResult {
    axmono::syscall::signal::sys_rt_sigreturn()
}

#[inline]
pub fn sys_rt_sigsuspend(mask_ptr: usize, sigsetsize: usize) -> SyscallResult {
    axmono::syscall::signal::sys_rt_sigsuspend(mask_ptr, sigsetsize)
}



