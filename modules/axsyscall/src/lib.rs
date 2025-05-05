#![cfg_attr(not(test), no_std)]
#![feature(stmt_expr_attributes)]
// #![cfg(test)]

mod test;
extern crate axlog;
use axerrno::LinuxError;
mod syscall_imp;
use arceos_posix_api::ctypes;
use core::ffi::*;
pub mod result;
pub use result::{SyscallResult, ToLinuxResult};
#[cfg(all(feature = "fs", feature = "fd"))]
use syscall_imp::fs::{sys_chdir, sys_getdents};
use syscall_imp::sys::sys_uname;

#[macro_export]
macro_rules! syscall_handler_def {
    ($($(#[$attr:meta])* $sys:ident => $args:tt $body:expr $(,)?)*) => {
        #[axhal::trap::register_trap_handler(axhal::trap::SYSCALL)]
        pub fn handle_syscall(args: &[usize; 6], syscall_num: usize) -> Option<isize> {
            use axhal::arch::ITrapFrame;
            use syscalls::Sysno;
            use $crate::result::{SyscallResult, LinuxResultToIsize};
            //let args = [tf.arg0(), tf.arg1(), tf.arg2(), tf.arg3(), tf.arg4(), tf.arg5()];
            let sys_id = Sysno::from(syscall_num as u32);

            let result:Option<SyscallResult> = match sys_id {
                $(
                    $(#[$attr])*
                    Sysno::$sys => {
                            //axlog::debug!("handle syscall: {}({:x?})", stringify!($sys), args);
                            // TODO: remove #![feature(stmt_expr_attributes)]
                        Some((
                            #[inline(always)]
                            || -> SyscallResult {
                                let $args = *args;
                                $body
                        })())
                    }
                ),*,
                _ => {
                        //axlog::debug!("handle syscall: {}({:?})", stringify!(none), args);
                        None
                }
            };
            result.map(|r| r.as_isize())
        }
    };
}

macro_rules! apply {
    ($fn:expr, $($arg:ident),* $(,)?) => {
        $fn($($arg as _),*)
    };
}
/*
 *macro_rules! get_args {
 *    ($($arg:ident),* $(,)?) => {
 *        let [$($arg),* ..] = args;
 *    };
 *}
 */

syscall_handler_def!(
        write => [fd,buf_ptr,size,..] {
            let buf = unsafe { core::slice::from_raw_parts(buf_ptr as _, size) };
            syscall_imp::io::sys_write(fd, buf)
        }

        read => [fd, buf_ptr, size, ..] {
            let buf = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, size) };
            syscall_imp::io::sys_read(fd, buf)
        }

        writev => [fd, iov, iocnt, ..] {
            apply!(syscall_imp::io::sys_writev, fd, iov, iocnt)
        }
        // 文件操作相关系统调用
        #[cfg(all(feature = "fs", feature = "fd"))]
        openat => [dirfd, fname, flags, mode, ..] {
            apply!(syscall_imp::fs::sys_openat, dirfd, fname, flags, mode)
        }

        #[cfg(all(feature = "fs", feature = "fd"))]
        close => [fd, ..] {
            apply!(syscall_imp::fd::sys_close, fd)
        }

        #[cfg(all(feature = "fs", target_arch = "x86_64"))]
        unlink => [path_name, ..] {
             apply!(syscall_imp::fs::sys_unlink, path_name)
        }

        #[cfg(all(feature = "fs", feature = "fd"))]
        unlinkat => [dirfd, path_name, ..] {
             apply!(syscall_imp::fs::sys_unlinkat, dirfd, path_name)
        }

        #[cfg(all(feature = "fs", feature = "fd"))]
        statfs => _args {
            todo!()
        }

        #[cfg(all(feature = "fs", feature = "fd"))]
        chdir => [path, ..] apply!(sys_chdir, path),
        // TODO: handle dir_fd and prem
        #[cfg(all(feature = "fs", feature = "fd"))]
        mkdirat => [dir_fd, path, perm, ..] {
            apply!(syscall_imp::fs::sys_mkdirat, dir_fd, path, perm)
        }
        #[cfg(all(feature = "fs", feature = "fd"))]
        getdents64 => [fd, buf, count, ..] {
            //apply!(sys_getdents, fd, buf, count)
            let count:c_int = count.try_into().unwrap();
            sys_getdents(fd as _, buf as _, count)
        }

        /*
         *#[cfg(all(feature = "fs", feature = "fd"))]
         *fstat => [fd, buf, ..] {
         *    unsafe { apply!(syscall_imp::fs::sys_fstat, fd, buf) }
         *}
         */

        #[cfg(all(feature = "fs", feature = "fd"))]
        fstat => [fd, buf, ..] {
            unsafe { apply!(syscall_imp::fs::sys_fstat, fd, buf) }
        }

        #[cfg(target_arch = "riscv64")]
        #[cfg(all(feature = "fs", feature = "fd"))]
        fstatat => [dir_fd, pathname, buf, flags, ..] {
            unsafe { apply!(syscall_imp::fs::sys_fstatat, dir_fd, pathname, buf, flags) }
        }


        #[cfg(all(feature = "fs", feature = "fd"))]
        lseek => [fd, offset, whence, ..] {
            apply!(syscall_imp::fs::sys_lseek, fd, offset, whence)
        }

        #[cfg(all(feature = "fs", feature = "fd"))]
        getcwd => [buf, size, ..] {
            apply!(syscall_imp::fs::sys_getcwd, buf, size)
        }

        #[cfg(all(feature = "fs", feature = "fd"))]
        renameat => [old, new, ..] {
            apply!(syscall_imp::fs::sys_rename, old, new)
        }

        #[cfg(all(feature = "fs", feature = "fd"))]
        dup => [old_fd, ..] {
            apply!(syscall_imp::fd::sys_dup, old_fd)
        }

        #[cfg(all(feature = "fs", feature = "fd"))]
        dup3 => [old_fd, new_fd, ..] {
            apply!(syscall_imp::fd::sys_dup3, old_fd, new_fd)
        }

        #[cfg(all(feature = "fs", feature = "fd"))]
        fcntl => [fd, cmd, arg, ..] {
            apply!(syscall_imp::fd::sys_fcntl, fd, cmd, arg)
        }
        #[cfg(feature = "pipe")]
        pipe2 => [fds, ..] {
            let fds = unsafe { core::slice::from_raw_parts_mut(fds as *mut c_int, 2) };
            syscall_imp::pipe::sys_pipe(fds)
        }

        // 进程控制相关系统调用
        exit => [code,..] {
            apply!(syscall_imp::task::sys_exit, code)
        }
        getpid => _ syscall_imp::task::sys_getpid()
        gettid => _ syscall_imp::task::sys_gettid()
        sched_yield => _ syscall_imp::task::sys_yield()
        // 时间相关系统调用
        clock_gettime => args {
            let cls = args[0];
            let ts: *mut ctypes::timespec = args[1] as *mut ctypes::timespec;
            syscall_imp::time::sys_clock_gettime(cls as ctypes::clockid_t, ts)
        }
        clock_gettime64 => args {
            let cls = args[0];
            let ts: *mut ctypes::timespec = args[1] as *mut ctypes::timespec;
            syscall_imp::time::sys_clock_gettime(cls as ctypes::clockid_t, ts)
        }
        gettimeofday => args {
            let ts: *mut ctypes::timeval = args[0] as *mut ctypes::timeval;
            syscall_imp::time::sys_get_time_of_day(ts)
        }
        nanosleep => args {
            let req: *const ctypes::timespec = args[0] as *const ctypes::timespec;
            let rem: *mut ctypes::timespec = args[1] as *mut ctypes::timespec;
            syscall_imp::time::sys_nanosleep(req, rem)
        }
        clock_nanosleep_time64 => args {
            // TODO: handle clock_id and flags
            let _clock_id = args[0];
            let _flags = args[1];
            let req: *const ctypes::timespec = args[2] as *const ctypes::timespec;
            let rem: *mut ctypes::timespec = args[3] as *mut ctypes::timespec;
            syscall_imp::time::sys_nanosleep(req, rem)
        }
        // 其他系统调用
        uname => [buf, ..] apply!(sys_uname, buf),

        //网络相关
        #[cfg(feature = "net")]
        socket => [domain, socktype, protocol, ..] {
            apply!(syscall_imp::net::sys_socket, domain, socktype, protocol)
        }
        #[cfg(feature = "net")]
        bind => [fd, addr, addrlen, ..] {
            apply!(syscall_imp::net::sys_bind, fd, addr, addrlen)
        }
        #[cfg(feature = "net")]
        // fd, addr, addrlen
        connect => [fd, addr, addrlen, ..] {
            apply!(syscall_imp::net::sys_connect, fd, addr, addrlen)
        }
        #[cfg(feature = "net")]
        // fd, buf, len, flags, addr, addrlen
        sendto => [fd, buf, len, flags, addr, addrlen, ..] {
            apply!(syscall_imp::net::sys_sendto, fd, buf, len, flags, addr, addrlen)
        }

        #[cfg(feature = "net")]
        // fd, buf, len, flags
        sendmsg => [fd, buf, len, flags, ..] {
            apply!(syscall_imp::net::sys_send, fd, buf, len, flags)
        }

        #[cfg(feature = "net")]
        // fd, buf, len, flags, addr, addrlen
        recvfrom => [fd, buf, len, flags, addr, addrlen, ..] {
            unsafe { apply!(syscall_imp::net::sys_recvfrom, fd, buf, len, flags, addr, addrlen) }
        }

        #[cfg(feature = "net")]
        // fd, buf, len, flags
        recvmsg => [fd, buf, len, flags, ..] {
            apply!(syscall_imp::net::sys_recv, fd, buf, len, flags)
        }

        #[cfg(feature = "net")]
        // fd, backlog
        listen => [fd, backlog, ..] {
            apply!(syscall_imp::net::sys_listen, fd, backlog)
        }

        #[cfg(feature = "net")]
        // fd, addr, addrlen
        accept => [fd, addr, addrlen, ..] {
            unsafe { apply!(syscall_imp::net::sys_accept, fd, addr, addrlen) }
        }

        #[cfg(feature = "net")]
        // fd, how
        shutdown => [fd, how, ..] {
            apply!(syscall_imp::net::sys_shutdown, fd, how)
        }

        #[cfg(feature = "net")]
        // fd, addr, addrlen
        getsockname => [fd, addr, addrlen, ..] {
            unsafe { apply!(syscall_imp::net::sys_getsockname, fd, addr, addrlen) }
        }

        #[cfg(feature = "net")]
        // fd, addr, addrlen
        getpeername => [fd, addr, addrlen, ..] {
            unsafe { apply!(syscall_imp::net::sys_getpeername, fd, addr, addrlen) }
        }

);
