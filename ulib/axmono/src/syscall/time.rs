use arceos_posix_api::ctypes::tms;
use axerrno::{AxError, LinuxResult};
use axhal::time::nanos_to_ticks;
use axtask::{TaskExtRef, current};
use core::convert::TryInto;
use linux_raw_sys::general::{itimerval, timeval};

use crate::task::{ItimerConfig, timer};

fn cov(t: u64) -> i64 {
    t.min(i64::MAX as u64).try_into().unwrap()
}

pub fn sys_times(tms_ptr: usize) -> LinuxResult<isize> {
    let curr_task = current();
    let (utime_ns, stime_ns) = curr_task.task_ext().time_stat_output();
    let utime = nanos_to_ticks(utime_ns.try_into().map_err(|_| AxError::BadState)?);
    let stime = nanos_to_ticks(stime_ns.try_into().map_err(|_| AxError::BadState)?);
    let tms = tms {
        tms_utime: cov(utime),
        tms_stime: cov(stime),
        tms_cutime: cov(utime),
        tms_cstime: cov(utime),
    };
    unsafe {
        *(tms_ptr as *mut tms) = tms;
    }
    Ok(0)
}

/// 实现 setitimer 系统调用
pub fn sys_setitimer(
    which: i32,
    new_value: *const itimerval,
    old_value: *mut itimerval,
) -> LinuxResult<isize> {
    // 验证参数
    if which < 0 || which > 2 {
        return Err(axerrno::LinuxError::EINVAL);
    }

    if new_value.is_null() {
        return Err(axerrno::LinuxError::EFAULT);
    }

    // 从用户空间读取新的定时器值
    let new_itimer = unsafe { *new_value };

    // 转换为内部格式
    let new_config = ItimerConfig {
        interval_sec: new_itimer.it_interval.tv_sec as u64,
        interval_usec: new_itimer.it_interval.tv_usec as u64,
        value_sec: new_itimer.it_value.tv_sec as u64,
        value_usec: new_itimer.it_value.tv_usec as u64,
    };

    // 设置定时器
    let old_config = if !old_value.is_null() {
        let mut old_config = ItimerConfig::default();
        timer::set_itimer(which, &new_config, Some(&mut old_config))?;
        old_config
    } else {
        timer::set_itimer(which, &new_config, None)?;
        ItimerConfig::default()
    };

    // 如果用户请求旧值，则填充
    if !old_value.is_null() {
        unsafe {
            *old_value = itimerval {
                it_interval: timeval {
                    tv_sec: old_config.interval_sec as i64,
                    tv_usec: old_config.interval_usec as i64,
                },
                it_value: timeval {
                    tv_sec: old_config.value_sec as i64,
                    tv_usec: old_config.value_usec as i64,
                },
            };
        }
    }

    Ok(0)
}

/// 实现 getitimer 系统调用
pub fn sys_getitimer(which: i32, curr_value: *mut itimerval) -> LinuxResult<isize> {
    // 验证参数
    if which < 0 || which > 2 {
        return Err(axerrno::LinuxError::EINVAL);
    }

    if curr_value.is_null() {
        return Err(axerrno::LinuxError::EFAULT);
    }

    // 获取当前定时器配置
    let mut curr_config = ItimerConfig::default();
    timer::get_itimer(which, &mut curr_config)?;

    // 填充用户空间结构
    unsafe {
        *curr_value = itimerval {
            it_interval: timeval {
                tv_sec: curr_config.interval_sec as i64,
                tv_usec: curr_config.interval_usec as i64,
            },
            it_value: timeval {
                tv_sec: curr_config.value_sec as i64,
                tv_usec: curr_config.value_usec as i64,
            },
        };
    }

    Ok(0)
}
