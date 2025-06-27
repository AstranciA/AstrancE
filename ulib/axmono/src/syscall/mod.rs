use core::{
    error,
    ffi::{CStr, c_char, c_void},
};

use crate::task::ThreadData;
use crate::{
    ctypes::{CloneFlags, WaitStatus},
    mm::mmap::MmapIOImpl,
    task::{self, time_stat_from_user_to_kernel, time_stat_output},
};
use alloc::{string::String, sync::Arc, vec::Vec};
use arceos_posix_api::{
    self as api, char_ptr_to_str, ctypes::*, get_file_like, str_vec_ptr_to_str, sys_read,
};
use axerrno::{AxError, LinuxError};
use axfs::{CURRENT_DIR, api::set_current_dir, fops::Directory};
use axhal::trap::{PRE_TRAP, register_trap_handler};
use axhal::{arch::TrapFrame, time::nanos_to_ticks};
use axmm::{MmapFlags, MmapPerm};
// use axsyscall::{ToLinuxResult, apply, syscall_handler_def};
use axtask::{CurrentTask, TaskExtMut, TaskExtRef, current};
use core::ffi::c_int;
use linux_raw_sys::general as linux;
use memory_addr::MemoryAddr;
use syscalls::Sysno;

pub mod mm;
pub mod process;
pub mod signal;
pub mod time;

pub use mm::*;
pub use process::*;
pub use signal::*;
pub use time::*;

/*
syscall_handler_def!(
        exit => [code,..] {
            task::sys_exit((code & 0xff) as i32)
        }
        exit_group => [code,..]{
            task::exit::sys_exit_group((code & 0xff) as i32)
        }
        clone => [flags, sp, ..] {
            let clone_flags = CloneFlags::from_bits_retain(flags as u32);

            let child_task = task::clone_task(
                if (sp != 0) { Some(sp) } else { None },
                clone_flags,
                true,
            )?;
            Ok(child_task.task_ext().thread.process().pid() as isize)
        }
        wait4 => [pid, wstatus, options, reusage, ..] {
            let curr = current();
            crate::sys_waitpid(
                pid as i32,
                wstatus.into(),
                options as u32
            )
        }
        execve => [pathname, argv, envp, ..] {
            let pathname = char_ptr_to_str(pathname as *const c_char)?;
            let argv: Vec<String> = str_vec_ptr_to_str(argv as *const *const c_char)?.into_iter().map(|s| String::from(s)).collect();
            let envp: Vec<String> = str_vec_ptr_to_str(envp as *const *const c_char)?.into_iter().map(|s| String::from(s)).collect();

            let err = task::exec_current(
                pathname,
                &argv.as_slice(),
                &envp.as_slice()
            ).expect_err("successful execve should not reach here");
            Err(err.into())
        }
        brk => [brk, ..] {
            apply!(mm::sys_brk, brk)
        }
        set_tid_address => args {
                let tidptr = args[0];
                let tid: usize = current().task_ext().thread.tid() as _;
                current().task_ext().thread_data().set_clear_child_tid(tidptr);
                Ok(tid as isize)
        }
        mmap => [addr, len, prot, flags, fd, off, ..] {
            apply!(mm::sys_mmap, addr, len, prot, flags, fd, off)
        }
        munmap => args {
            let curr = current();
            let mut aspace = curr.task_ext().process_data().aspace.lock();
            let start = args[0].into();
            let size = args[1].align_up_4k();
            if aspace.munmap(start, size).is_ok() {
                Ok(0)
            } else {
                // TODO
                Err(LinuxError::EPERM)
            }
        }
        mprotect => [addr, size, prot, ..] {
            apply!(mm::sys_mprotect, addr, size, prot)
        }
        getpid => _ {
            Ok(current().task_ext().thread.process().pid() as _)
        }
        gettid => _ {
            Ok(current().task_ext().thread.tid() as _)
        }
        getppid => _ {
            current().task_ext().thread.process().parent().map(|p|p.pid() as _).ok_or(LinuxError::EINVAL)
        }
        getgid => _ {
            Ok(current().task_ext().thread.process().group().pgid() as _)
        }
        getuid => _{
            Ok(0)
            //TODO: to acomplish the puid()
            // Ok(current().task_ext().thread.process().group().puid() as _)
        }
        geteuid => _{
            //TODO:geteuid ::returns the effective user ID of the calling process
            Ok(0)
        }
        getegid => _ {
            //getegid::returns the effective group ID of the calling process
            Ok(0)
        }
        // FIXME: cutime cstimes
        times => args {
            let curr_task = current();
            let (utime_ns, stime_ns) = curr_task.task_ext().time_stat_output();
            let utime = nanos_to_ticks(utime_ns.try_into().map_err(|_| AxError::BadState)?);
            let stime = nanos_to_ticks(stime_ns.try_into().map_err(|_| AxError::BadState)?);
            let tms = api::ctypes::tms {
                tms_utime: utime.try_into().unwrap(),
                tms_stime: stime.try_into().unwrap(),
                tms_cutime: utime.try_into().unwrap(),
                tms_cstime: stime.try_into().unwrap(),
            };
            unsafe {
                *(args[0] as *mut api::ctypes::tms) = tms;
            }
            Ok(0)
            //unsafe { core::slice::from_raw_parts_mut(args[0] as *mut api::ctypes::tms, 1).copy_from_slice(tms); }
        }
        rt_sigaction => [signum, act, oldact, ..] {
            task::signal::sys_sigaction(signum.try_into().map_err(|_| LinuxError::EINVAL)?, act as _, oldact as _).map_err(|_| panic!("1"))
        }
        rt_sigprocmask => [how, set, oldset, ..] {
            task::signal::sys_sigprocmask(how.try_into().map_err(|_| LinuxError::EINVAL)?, set as _, oldset as _)
        }
        rt_sigtimedwait => [set, info, timeout, ..] {
            task::signal::sys_sigtimedwait(set as _, info as _, timeout as _).map(|sig| sig as isize)
        }
        rt_sigreturn => _ {
            task::signal::sys_sigreturn()
        }
        rt_sigsuspend => [mask_ptr,sigsetsize,..]{
            task::signal::sys_rt_sigsuspend(mask_ptr as _,sigsetsize as _)
        }
        kill => [pid, sig, ..] {
            task::signal::sys_kill(pid as _, sig as _)
        }
        //FIXME incomplete！
        setxattr => _ {
            Ok(0)
        }
        futex => _ {
            warn!("futex syscall not implemented, task exit");
            //task::exit::do_exit(-1 << 8, true);
            task::sys_exit(-1);
            //Ok(0)
            //Err(LinuxError::ENOSYS)
        }
);
*/
fn foo() {
    //LinuxError::ENOSYS
}
