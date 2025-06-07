use crate::ctypes;
use crate::ctypes::pid_t;
use axerrno::LinuxError;
use core::ffi::c_int;

/// Get resource limitations
///
/// TODO: support more resource types
pub unsafe fn sys_getrlimit(resource: c_int, rlimits: *mut ctypes::rlimit) -> c_int {
    debug!("sys_getrlimit <= {} {:#x}", resource, rlimits as usize);
    syscall_body!(sys_getrlimit, {
        match resource as u32 {
            ctypes::RLIMIT_DATA => {}
            ctypes::RLIMIT_STACK => {}
            ctypes::RLIMIT_NOFILE => {}
            _ => return Err(LinuxError::EINVAL),
        }
        if rlimits.is_null() {
            return Ok(0);
        }
        match resource as u32 {
            ctypes::RLIMIT_STACK => unsafe {
                (*rlimits).rlim_cur = axconfig::TASK_STACK_SIZE as _;
                (*rlimits).rlim_max = axconfig::TASK_STACK_SIZE as _;
            },
            #[cfg(feature = "fd")]
            // ctypes::RLIMIT_NOFILE => unsafe {
            //     (*rlimits).rlim_cur = super::fd_ops::AX_FILE_LIMIT as _;
            //     (*rlimits).rlim_max = super::fd_ops::AX_FILE_LIMIT as _;
            // },
            ctypes::RLIMIT_NOFILE => unsafe {
                (*rlimits).rlim_cur = super::fd_ops::get_file_limit() as _;
                (*rlimits).rlim_max = super::fd_ops::get_file_limit_max() as _;
            },
            _ => {}
        }
        Ok(0)
    })
}

/// Set resource limitations
///
/// TODO: support more resource types
// pub unsafe fn sys_setrlimit(resource: c_int, rlimits: *mut crate::ctypes::rlimit) -> c_int {
//     debug!("sys_setrlimit <= {} {:#x}", resource, rlimits as usize);
//     syscall_body!(sys_setrlimit, {
//         match resource as u32 {
//             crate::ctypes::RLIMIT_DATA => {}
//             crate::ctypes::RLIMIT_STACK => {}
//             crate::ctypes::RLIMIT_NOFILE => {}
//             _ => return Err(LinuxError::EINVAL),
//         }
//         // Currently do not support set resources
//         Ok(0)
//     })
// }
// 修改 sys_setrlimit 函数
pub unsafe fn sys_setrlimit(resource: c_int, rlimits: *mut ctypes::rlimit) -> c_int {
    debug!("sys_setrlimit <= {} {:#x}", resource, rlimits as usize);
    syscall_body!(sys_setrlimit, {
        if rlimits.is_null() {
            return Err(LinuxError::EFAULT);
        }
        let rlim = unsafe { *rlimits };
        match resource as u32 {
            ctypes::RLIMIT_NOFILE => {
                #[cfg(feature = "fd")]
                {
                    // 检查新限制是否有效
                    if rlim.rlim_cur > rlim.rlim_max {
                        return Err(LinuxError::EINVAL);
                    }
                    // 尝试设置新的限制
                   super::fd_ops::set_file_limit(rlim.rlim_cur as usize, rlim.rlim_max as usize)?;

                }
                Ok(0)
            }
            _ => Err(LinuxError::EINVAL),
        }
    })
}

pub unsafe fn sys_prlimit64(
    pid: pid_t,
    resource: c_int,
    new_limit: *mut ctypes::rlimit,
    old_limit: *mut ctypes::rlimit,
) -> c_int {
    debug!(
        "sys_prlimit64 <= pid: {}, resource: {}, new: {:#x}, old: {:#x}",
        pid, resource, new_limit as usize, old_limit as usize
    );
    syscall_body!(sys_prlimit64, {
        // 1. 获取目标进程（目前仅支持当前进程 pid==0）
        //TODO:support:pid != 0
        if pid != 0 {
            return Err(LinuxError::EINVAL); // 
        }
        if !old_limit.is_null() {
            unsafe { sys_getrlimit(resource, old_limit) };
        }
        if !new_limit.is_null() {
            unsafe { sys_setrlimit(resource, new_limit) };
        }
        Ok(0)
    })
}
