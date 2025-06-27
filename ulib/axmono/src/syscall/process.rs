use crate::task;
use crate::ctypes::CloneFlags;
use alloc::string::String;
use alloc::vec::Vec;
use axerrno::{AxError, LinuxError, LinuxResult};
use axtask::{current, TaskExtRef};
use arceos_posix_api::{char_ptr_to_str, str_vec_ptr_to_str};
use core::ffi::c_char;

pub fn sys_exit(code: i32) -> LinuxResult<isize> {
    task::sys_exit(code);
    Ok(0)
}

pub fn sys_exit_group(code: i32) -> LinuxResult<isize> {
    task::exit::sys_exit_group(code);
    Ok(0)
}

pub fn sys_clone(flags: usize, sp: usize) -> LinuxResult<isize> {
    let clone_flags = CloneFlags::from_bits_retain(flags as u32);
    let child_task = task::clone_task(
        if sp != 0 { Some(sp) } else { None },
        clone_flags,
        true,
    )?;
    Ok(child_task.task_ext().thread.process().pid() as isize)
}

pub fn sys_wait4(pid: i32, wstatus: usize, options: u32) -> LinuxResult<isize> {
    crate::sys_waitpid(pid, wstatus.into(), options)
}

pub fn sys_execve(pathname: usize, argv: usize, envp: usize) -> LinuxResult<isize> {
    let pathname = char_ptr_to_str(pathname as *const c_char)?;
    let argv: Vec<String> = str_vec_ptr_to_str(argv as *const *const c_char)?.into_iter().map(String::from).collect();
    let envp: Vec<String> = str_vec_ptr_to_str(envp as *const *const c_char)?.into_iter().map(String::from).collect();
    let err = task::exec_current(pathname, &argv, &envp).expect_err("successful execve should not reach here");
    Err(err.into())
}

pub fn sys_set_tid_address(tidptr: usize) -> LinuxResult<isize> {
    let tid: usize = current().task_ext().thread.tid() as _;
    current().task_ext().thread_data().set_clear_child_tid(tidptr);
    Ok(tid as isize)
}

pub fn sys_getpid() -> LinuxResult<isize> {
    Ok(current().task_ext().thread.process().pid() as _)
}

pub fn sys_gettid() -> LinuxResult<isize> {
    Ok(current().task_ext().thread.tid() as _)
}

pub fn sys_getppid() -> LinuxResult<isize> {
    current().task_ext().thread.process().parent().map(|p| p.pid() as _).ok_or(LinuxError::EINVAL)
}

pub fn sys_getgid() -> LinuxResult<isize> {
    Ok(current().task_ext().thread.process().group().pgid() as _)
}

pub fn sys_getuid() -> LinuxResult<isize> {
    Ok(0)
    // TODO: 完善 puid
    // Ok(current().task_ext().thread.process().group().puid() as _)
}

pub fn sys_geteuid() -> LinuxResult<isize> {
    Ok(0)
    // TODO: 返回有效用户ID
}

pub fn sys_getegid() -> LinuxResult<isize> {
    Ok(0)
    // TODO: 返回有效组ID
}

pub fn sys_kill(pid: i32, sig: i32) -> LinuxResult<isize> {
    task::signal::sys_kill(pid, sig)
}

pub fn sys_setxattr() -> LinuxResult<isize> {
    Ok(0)
}

pub fn sys_futex() -> LinuxResult<isize> {
    // warn!("futex syscall not implemented, task exit");
    task::sys_exit(-1);
}