use crate::ctypes::CloneFlags;
use crate::task;
use alloc::string::String;
use alloc::vec::Vec;
use arceos_posix_api::{char_ptr_to_str, str_vec_ptr_to_str};
use axerrno::{AxError, LinuxError, LinuxResult};
use axtask::{TaskExtRef, current};
use core::ffi::c_char;
// use crate::task::{ThreadData, RobustListHead};
// use core::mem;

pub fn sys_exit(code: i32) -> LinuxResult<isize> {
    task::sys_exit(code);
    Ok(0)
}

pub fn sys_exit_group(code: i32) -> LinuxResult<isize> {
    task::exit::sys_exit_group(code);
    Ok(0)
}

pub fn sys_clone(
    flags: usize,
    sp: usize,
    parent_tid: usize,
    a4: usize,
    a5: usize,
) -> LinuxResult<isize> {
    let clone_flags = CloneFlags::from_bits_retain(flags as u32);
    let child_tid = {
        #[cfg(any(target_arch = "x86_64", target_arch = "loongarch64"))]
        {
            a4
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "loongarch64")))]
        {
            a5
        }
    };
    let tls = {
        #[cfg(any(target_arch = "x86_64", target_arch = "loongarch64"))]
        {
            a5
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "loongarch64")))]
        {
            a4
        }
    };
    let child_task = task::clone_task(
        if (sp != 0) { Some(sp) } else { None },
        clone_flags,
        true,
        parent_tid,
        child_tid,
        tls,
    )?;
    //let child_task = task::clone_task(if sp != 0 { Some(sp) } else { None }, clone_flags, true)?;
    Ok(child_task.task_ext().thread.process().pid() as isize)
}

pub fn sys_wait4(pid: i32, wstatus: usize, options: u32) -> LinuxResult<isize> {
    crate::sys_waitpid(pid, wstatus.into(), options)
}

pub fn sys_execve(pathname: usize, argv: usize, envp: usize) -> LinuxResult<isize> {
    let pathname = char_ptr_to_str(pathname as *const c_char)?;
    let argv: Vec<String> = str_vec_ptr_to_str(argv as *const *const c_char)?
        .into_iter()
        .map(String::from)
        .collect();
    let envp: Vec<String> = str_vec_ptr_to_str(envp as *const *const c_char)?
        .into_iter()
        .map(String::from)
        .collect();
    let err = task::exec_current(pathname, &argv, &envp)
        .expect_err("successful execve should not reach here");
    Err(err.into())
}

pub fn sys_set_tid_address(tidptr: usize) -> LinuxResult<isize> {
    let tid: usize = current().task_ext().thread.tid() as _;
    current()
        .task_ext()
        .thread_data()
        .set_clear_child_tid(tidptr);
    Ok(tid as isize)
}

pub fn sys_getpid() -> LinuxResult<isize> {
    Ok(current().task_ext().thread.process().pid() as _)
}

pub fn sys_gettid() -> LinuxResult<isize> {
    Ok(current().task_ext().thread.tid() as _)
}

pub fn sys_getppid() -> LinuxResult<isize> {
    current()
        .task_ext()
        .thread
        .process()
        .parent()
        .map(|p| p.pid() as _)
        .ok_or(LinuxError::EINVAL)
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

pub fn sys_kill(pid: i32, sig: u32) -> LinuxResult<isize> {
    task::signal::sys_kill(pid, sig)
}

pub fn sys_tkill(pid: i32, sig: u32) -> LinuxResult<isize> {
    task::signal::sys_tkill(pid as u32, sig)
}


pub fn sys_setxattr() -> LinuxResult<isize> {
    Ok(0)
}

pub fn sys_futex() -> LinuxResult<isize> {
    // warn!("futex syscall not implemented, task exit");
    task::sys_exit(-1);
}

//TODO: the head_ptr type

// pub fn sys_set_robust_list(head_ptr: usize, size: usize) -> LinuxResult {
//     // size 必须等于用户态的 struct robust_list_head 大小
//     let expected = mem::size_of::<RobustListHead>();
//     if size != expected {
//         return Err(LinuxError::EINVAL);
//     }
//
//     // 简单的用户指针检查：0 表示 NULL，内核允许 NULL（表示没有 robust list）
//     // 进一步可用 validate_ptr(head_ptr, size, AccessType::Read) 来严格检查
//     if head_ptr == 0 {
//         // 清除
//         let binding = current();
//         let td = binding.task_ext().thread.data::<ThreadData>()
//             .ok_or(LinuxError::ESRCH)?; // 或其他合适的错误
//         td.set_robust_list(0, 0);
//         return Ok(());
//     }
//
//     // 这里仅记录 head 与 size；不去内核读取用户空间结构
//     let binding = current();
//     let td = binding.task_ext().thread.data::<ThreadData>()
//         .ok_or(LinuxError::ESRCH)?; // 或其他合适的错误
//     td.set_robust_list(head_ptr, size);
//
//     Ok(())
// }

// pub fn sys_get_robust_list(pid: i32, head_out_ptr: usize, size_out_ptr: usize) -> LinuxResult {
//     // 参数 head_out_ptr/size_out_ptr 为用户空间写出地址
//     // 简单检查：不能为 0（内核需要将结果写回用户）
//     if head_out_ptr == 0 || size_out_ptr == 0 {
//         return Err(LinuxError::EFAULT);
//     }
//
//     // 找到目标任务
//     let task = if pid == 0 {
//         current()
//     } else {
//         find_task_by_pid(pid as u64).ok_or(LinuxError::ESRCH)?
//     };
//
//     // 权限检查：这里简化为允许（真实内核有 ptrace 权限检查）
//     // 取出 thread data
//     let td = task.task_ext().thread.data::<ThreadData>()
//         .ok_or(LinuxError::ESRCH)?;
//
//     let (head, size) = td.get_robust_list();
//
//     // 把 head 和 size 写回用户空间
//     unsafe {
//         // head_out_ptr: *mut *mut robust_list_head
//         let head_ptr = head_out_ptr as *mut usize;
//         let size_ptr = size_out_ptr as *mut usize;
//         if head_ptr.is_null() || size_ptr.is_null() {
//             return Err(LinuxError::EFAULT);
//         }
//         // 使用 volatile write 或直接 write 都可（这里用普通 write）
//         core::ptr::write(head_ptr, head);
//         core::ptr::write(size_ptr, size);
//     }
//
//     Ok(())
// }
