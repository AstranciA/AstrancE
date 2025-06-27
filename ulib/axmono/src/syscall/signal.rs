use axerrno::LinuxResult;


pub fn sys_rt_sigaction(signum: i32, act: usize, oldact: usize) -> LinuxResult<isize> {
    crate::task::signal::sys_sigaction(signum, act as _, oldact as _).map_err(|_| panic!("1"))
}

pub fn sys_rt_sigprocmask(how: i32, set: usize, oldset: usize) -> LinuxResult<isize> {
    crate::task::signal::sys_sigprocmask(how, set as _, oldset as _)
}

pub fn sys_rt_sigtimedwait(set: usize, info: usize, timeout: usize) -> LinuxResult<isize> {
    crate::task::signal::sys_sigtimedwait(set as _, info as _, timeout as _).map(|sig| sig as isize)
}

pub fn sys_rt_sigreturn() -> LinuxResult<isize> {
    crate::task::signal::sys_sigreturn()
}

pub fn sys_rt_sigsuspend(mask_ptr: usize, sigsetsize: usize) -> LinuxResult<isize> {
    crate::task::signal::sys_rt_sigsuspend(mask_ptr as _, sigsetsize as _)
}