use core::{
    error,
    ffi::{CStr, c_char, c_void},
};

use crate::{
    ctypes::{CloneFlags, WaitStatus},
    mm::mmap::MmapIOImpl,
    task::{self, time_stat_from_user_to_kernel, time_stat_ns, time_stat_output},
};
use alloc::{string::String, sync::Arc, vec::Vec};
use axhal::{arch::ITrapFrame, trap::{register_trap_handler, PRE_TRAP}};
use arceos_posix_api::{self as api, char_ptr_to_str, get_file_like, str_vec_ptr_to_str, sys_read};
use axerrno::{AxError, LinuxError};
use axfs::{CURRENT_DIR, api::set_current_dir, fops::Directory};
use axhal::{arch::TrapFrame, time::nanos_to_ticks};
use axmm::{MmapFlags, MmapPerm};
use axsyscall::{ToLinuxResult, syscall_handler_def};
use axtask::{CurrentTask, TaskExtMut, TaskExtRef, current};
use core::ffi::c_int;
use memory_addr::MemoryAddr;
use syscalls::Sysno;

syscall_handler_def!(
        clone => args {
            let curr = current();
            let clone_flags = CloneFlags::from_bits(args[0] as u32);
            if clone_flags.is_none() {
                error!("Invalid clone flags: {:x}", args[0]);
                return Err(LinuxError::EINVAL);
            }
            let clone_flags = clone_flags.unwrap();
            let sp = args[1];

            let child_task = task::clone_task(
                curr.as_task_ref().clone(),
                if (sp != 0) { Some(sp) } else { None },
                clone_flags,
                true,
            )
            .unwrap();
            axtask::spawn_task_by_ref(child_task.clone());
            Ok(child_task.id().as_u64() as isize)
        }
        wait4 => args {
            let curr = current();
            // FIXME: error code
            let mut result = Err(LinuxError::EPERM);
            while let wait_result = task::wait_pid(
                curr.as_task_ref().clone(),
                args[0] as i32,
                args[1] as *mut i32,
            ) {
                let r = match wait_result {
                    Ok(pid) => {
                        result = Ok(pid as isize);
                        break;
                    }
                    Err(WaitStatus::NotExist) => {
                        result = Ok(0);
                        break;
                    }
                    Err(e) => {
                        debug!("wait4: {:?}, keep waiting...", e);
                    }
                };
            }
            result
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
        brk => args {
            let res = (|| -> axerrno::LinuxResult<_> {
                let current_task = current();
                let old_top = current_task.task_ext().heap_top();
                if (args[0] != 0) {
                    current_task.task_ext().set_heap_top(args[0].into());
                }
                Ok(old_top)
            })();
            match res {
                Ok(v) => {
                    debug!("sys_brk => {:?}", res);
                    let v_: usize = v.try_into().unwrap();
                    Ok(v_ as isize)
                }
                Err(_) => {
                    info!("sys_brk => {:?}", res);
                    (-1).to_linux_result()
                }
            }
        }
        mmap => args {
            let curr = current();
            let mut aspace = curr.task_ext().aspace.lock();
            let perm = MmapPerm::from_bits(args[2]).ok_or(LinuxError::EINVAL)?;
            let flags = MmapFlags::from_bits(args[3]).ok_or(LinuxError::EINVAL)?;
            let fd = args[4];
            //let file = get_file_like(args[4].try_into().unwrap()).expect("invalid file descriptor");
            let offset = args[5];
            error!("mmap flags: {flags:?}, perm: {perm:?}");
            if let Ok(va) = aspace.mmap(
                args[0].into(),
                args[1],
                perm,
                flags,
                Arc::new(MmapIOImpl {
                    fd: fd as c_int,
                    file_offset: offset.try_into().unwrap(),
                    flags
                }),
                false,
            ) {
                return Ok(va.as_usize() as isize);
            }
            Err(LinuxError::EPERM)
        }
        munmap => args {
            let curr = current();
            let mut aspace = curr.task_ext().aspace.lock();
            let start = args[0].into();
            let size = args[1].align_up_4k();
            if aspace.munmap(start, size).is_ok() {
                Ok(0)
            } else {
                // TODO
                Err(LinuxError::EPERM)
            }
        }
        getppid => args {
            let curr = current();
            (curr.task_ext().get_parent() as isize).to_linux_result()
        }
        // FIXME: cutime cstimes
        times => args {
            let (utime_ns, stime_ns) = time_stat_ns();
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
);

/*
 *#[register_trap_handler(PRE_TRAP)]
 *fn pre_trap_handler(trap_frame: &TrapFrame) -> bool {
 *    trace!("trap from 0x{:x?}", trap_frame.get_ip());
 *    true
 *}
 */
