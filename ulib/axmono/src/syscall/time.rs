use axerrno::{AxError, LinuxResult};
use axtask::{current, TaskExtRef};
use axhal::time::nanos_to_ticks;
use arceos_posix_api::ctypes::tms;
use core::convert::TryInto;

pub fn sys_times(tms_ptr: usize) -> LinuxResult<isize> {
    let curr_task = current();
    let (utime_ns, stime_ns) = curr_task.task_ext().time_stat_output();
    let utime = nanos_to_ticks(utime_ns.try_into().map_err(|_| AxError::BadState)?);
    let stime = nanos_to_ticks(stime_ns.try_into().map_err(|_| AxError::BadState)?);
    let tms = tms {
        tms_utime: utime.try_into().unwrap(),
        tms_stime: stime.try_into().unwrap(),
        tms_cutime: utime.try_into().unwrap(),
        tms_cstime: stime.try_into().unwrap(),
    };
    unsafe {
        *(tms_ptr as *mut tms) = tms;
    }
    Ok(0)
}