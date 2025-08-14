use crate::SyscallResult;
use crate::ToLinuxResult;

#[inline]
pub fn sys_exit(code: i32) -> SyscallResult {
    axmono::syscall::process::sys_exit(code)
}

#[inline]
pub fn sys_exit_group(code: i32) -> SyscallResult {
    axmono::syscall::process::sys_exit_group(code)
}

#[inline]
pub fn sys_clone(
    flags: usize,
    sp: usize,
    parent_tid: usize,
    a4: usize,
    a5: usize,
) -> SyscallResult {
    axmono::syscall::process::sys_clone(flags, sp, parent_tid, a4, a5)
}

#[inline]
pub fn sys_wait4(pid: i32, wstatus: usize, options: u32) -> SyscallResult {
    axmono::syscall::process::sys_wait4(pid, wstatus, options)
}

#[inline]
pub fn sys_execve(pathname: usize, argv: usize, envp: usize) -> SyscallResult {
    axmono::syscall::process::sys_execve(pathname, argv, envp)
}

#[inline]
pub fn sys_set_tid_address(tidptr: usize) -> SyscallResult {
    axmono::syscall::process::sys_set_tid_address(tidptr)
}

#[inline]
pub fn sys_getpid() -> SyscallResult {
    axmono::syscall::process::sys_getpid()
}

#[inline]
pub fn sys_gettid() -> SyscallResult {
    axmono::syscall::process::sys_gettid()
}

#[inline]
pub fn sys_getppid() -> SyscallResult {
    axmono::syscall::process::sys_getppid()
}

#[inline]
pub fn sys_getgid() -> SyscallResult {
    axmono::syscall::process::sys_getgid()
}

#[inline]
pub fn sys_getuid() -> SyscallResult {
    axmono::syscall::process::sys_getuid()
}

#[inline]
pub fn sys_geteuid() -> SyscallResult {
    axmono::syscall::process::sys_geteuid()
}

#[inline]
pub fn sys_getegid() -> SyscallResult {
    axmono::syscall::process::sys_getegid()
}

#[inline]
pub fn sys_kill(pid: i32, sig: u32) -> SyscallResult {
    axmono::syscall::process::sys_kill(pid, sig)
}

#[inline]
pub fn sys_tkill(pid: i32, sig: u32) -> SyscallResult {
    axmono::syscall::process::sys_tkill(pid, sig)
}

/*
 *#[inline]
 *pub fn sys_tgkill(pid: i32, sig: u32) -> SyscallResult {
 *    axmono::syscall::process::sys_tgkill(pid, sig)
 *}
 */

#[inline]
pub fn sys_setxattr() -> SyscallResult {
    axmono::syscall::process::sys_setxattr()
}

#[inline]
pub fn sys_futex() -> SyscallResult {
    axmono::syscall::process::sys_futex()
}

#[inline]
pub fn sys_set_robust_list(head_ptr: usize, size: usize) -> SyscallResult {
    Ok(0)
}
