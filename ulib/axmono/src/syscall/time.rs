use arceos_posix_api::ctypes::tms;
use axerrno::{AxError, LinuxResult};
use axhal::time::nanos_to_ticks;
use axtask::{TaskExtRef, current};
use core::convert::TryInto;

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

