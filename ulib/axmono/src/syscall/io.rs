use core::{ffi::c_int, ptr::null_mut, time::Duration};

use arceos_posix_api::{
    FdSets,
    ctypes::{self, FD_SETSIZE},
    syscall_body, zero_fd_set,
};
use axerrno::{LinuxError, LinuxResult};
use axhal::time::monotonic_time;
use axtask::{current, yield_now, TaskExtRef};
use linux_raw_sys::general::*;

use crate::task::sys_sigprocmask;

pub unsafe fn sys_pselect(
    nfds: c_int,
    readfds: *mut ctypes::fd_set,
    writefds: *mut ctypes::fd_set,
    exceptfds: *mut ctypes::fd_set,
    timeout: *const ctypes::timespec,
    sigmask: *const sigset_t,
) -> LinuxResult<isize> {
    debug!(
        "sys_pselect <= {} {:#x} {:#x} {:#x}",
        nfds, readfds as usize, writefds as usize, exceptfds as usize
    );

    // 1. 参数验证
    if nfds < 0 {
        return Err(LinuxError::EINVAL);
    }
    let nfds = (nfds as usize).min(FD_SETSIZE as usize);

    // 2. 处理信号掩码（原子性修改）
    let old_sigmask = if !sigmask.is_null() {
        let new_mask = unsafe { *sigmask };
        Some(sys_sigprocmask(SIG_SETMASK as i32, sigmask, null_mut())?)
    } else {
        None
    };

    // 3. 处理超时
    let deadline = if !timeout.is_null() {
        let ts = unsafe { timeout.as_ref().ok_or(LinuxError::EFAULT)? };
        // 检查立即返回的特殊情况（timeout=0）
        if ts.tv_sec == 0 && ts.tv_nsec == 0 {
            // 立即返回，不阻塞
            let res = unsafe {
                zero_fd_set(readfds, nfds);
                zero_fd_set(writefds, nfds);
                zero_fd_set(exceptfds, nfds);
                FdSets::from(nfds, readfds, writefds, exceptfds)
                    .poll_all(readfds, writefds, exceptfds)?
            };

            // 恢复信号掩码
            if let Some(old_mask) = old_sigmask {
                sys_sigprocmask(SIG_SETMASK as i32, &old_mask as *const _ as _, null_mut())?;
            }

            return Ok(res as isize);
        }
        Some(monotonic_time() + Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32))
    } else {
        None // 无限等待
    };

    // 4. 主循环
    let fd_sets = FdSets::from(nfds, readfds, writefds, exceptfds);
    unsafe {
        zero_fd_set(readfds, nfds);
        zero_fd_set(writefds, nfds);
        zero_fd_set(exceptfds, nfds);
    }

    loop {
        #[cfg(feature = "net")]
        axnet::poll_interfaces();

        let res = fd_sets.poll_all(readfds, writefds, exceptfds)?;
        if res > 0 {
            // 恢复信号掩码
            if let Some(old_mask) = old_sigmask {
                sys_sigprocmask(SIG_SETMASK as i32, &old_mask as *const _ as _, null_mut())?;
            }
            return Ok(res as isize);
        }

        // 检查超时
        if let Some(deadline) = deadline {
            if monotonic_time() >= deadline {
                // 恢复信号掩码
                if let Some(old_mask) = old_sigmask {
                    sys_sigprocmask(SIG_SETMASK as i32, &old_mask as *const _ as _, null_mut())?;
                }
                return Ok(0);
            }
        }

        // 检查是否有待处理的信号
        if let Some(old_mask) = old_sigmask {
            let curr = current();
            if curr.task_ext().process_data().signal.lock().has_pending() {
                // 恢复信号掩码
                sys_sigprocmask(SIG_SETMASK as i32, &old_mask as *const _ as _, null_mut())?;
                return Err(LinuxError::EINTR);
            }
        }

        // 让出CPU
        yield_now();
    }
}
