#![cfg_attr(not(test), no_std)]
#![feature(stmt_expr_attributes)]
// #![cfg(test)]

mod test;
#[macro_use]
extern crate axlog;
use axerrno::LinuxError;
use syscall_imp::{
    fs::{sys_chdir, sys_getdents},
    sys::sys_uname,
};
// use axmono::ptr::{get_uspace, validate_reabable};
mod syscall_imp;
use arceos_posix_api::ctype_my::statx;
use arceos_posix_api::ctypes::{pid_t, timespec, timeval};
use arceos_posix_api::{ctypes, sys_listxattr, sys_pread64, sys_pwrite64};
use arceos_posix_api::SysInfo;
use axhal::paging::MappingFlags;
use axmono::validate_ptr;
use core::ffi::*;
use core::ptr;
use syscalls::Sysno::gettimeofday;

pub mod result;
mod utils;

use crate::syscall_imp::{fs, sys};
use crate::syscall_imp::fs::{
    sys_flistxattr, sys_fremovexattr, sys_fsetxattr, sys_utimesat, test_stat,
};
use crate::syscall_imp::io::sys_write;
use crate::syscall_imp::time::sys_get_time_of_day;
pub use result::{SyscallResult, ToLinuxResult};

#[macro_export]
macro_rules! syscall_handler_def {
    ($($(#[$attr:meta])* $sys:ident => $args:tt $body:expr $(,)?)*) => {
        #[axhal::trap::register_trap_handler(axhal::trap::SYSCALL)]
        pub fn handle_syscall(tf: &mut axhal::arch::TrapFrame, syscall_num: usize) -> Option<isize> {
            use syscalls::Sysno;
            use $crate::result::{SyscallResult, LinuxResultToIsize};
            let args = [tf.arg0(), tf.arg1(), tf.arg2(), tf.arg3(), tf.arg4(), tf.arg5()];
            let sys_id = Sysno::from(syscall_num as u32);
            let result:Option<SyscallResult> = match sys_id {
                $(
                    $(#[$attr])*
                    Sysno::$sys => {
                        axlog::debug!("handle syscall: {}({:x?})", stringify!($sys), args);
                        // TODO: remove #![feature(stmt_expr_attributes)]
                        Some((
                            #[inline(always)]
                            || -> SyscallResult {
                                let $args = args;
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

#[macro_export]
macro_rules! apply {
    ($fn:expr, $($arg:expr),* $(,)?) => {
        $fn($($arg as _),*)
    };
}

/*macro_rules! get_args {
     ($($arg:ident),* $(,)?) => {
        let [$($arg),* ..] = args;
     };
}*/

syscall_handler_def!(
        write => [fd, buf_ptr, size, ..] {
            // validate_ptr!(buf_ptr, u8, size, MappingFlags::WRITE);
            let buf = unsafe { core::slice::from_raw_parts(buf_ptr as *mut u8, size) };
            apply!(syscall_imp::io::sys_write, fd, buf)
        }

        read => [fd, buf_ptr, size, ..] {
            // validate_ptr!(buf_ptr, u8, size, MappingFlags::READ);
            let buf = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, size) };
            apply!(syscall_imp::io::sys_read, fd, buf)
        }

        readv => [fd, iov, iovcnt, ..] {
            // validate_ptr!(iov, ctypes::iovec, iovcnt, MappingFlags::WRITE);
            apply!(syscall_imp::io::sys_readv, fd, iov, iovcnt)
        }

        writev => [fd, iov, iovcnt, ..] {
            // validate_ptr!(iov, ctypes::iovec, iovcnt, MappingFlags::READ);
            apply!(syscall_imp::io::sys_writev, fd, iov, iovcnt)
        }
        #[cfg(all(feature = "fs", feature = "fd"))]
        renameat => [old_dirfd, old_path, new_dirfd, new_path, ..] {
            apply!(syscall_imp::fs::sys_renameat, old_dirfd, old_path, new_dirfd, new_path)
        }
        #[cfg(all(feature = "fs", feature = "fd"))]
        renameat2 => [old_dirfd, old_path, new_dirfd, new_path, ..] {
            apply!(syscall_imp::fs::sys_renameat, old_dirfd, old_path, new_dirfd, new_path)
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
        #[cfg(all(feature = "fs", feature = "fd"))]
        ioctl =>[fd,op,..]{
                Ok(0)
        }
        #[cfg(all(feature = "fs", feature = "fd"))]
        copy_file_range => [fd_in, off_in, fd_out, off_out, size, flag, ..]{
            apply!(syscall_imp::fd::sys_cp_file_range, fd_in, off_in, fd_out, off_out, size, flag,)
        }

        #[cfg(all(feature = "fs", feature = "fd"))]
        splice => [fd_in, off_in, fd_out, off_out, size, flag, ..]{
            apply!(syscall_imp::fd::sys_splice, fd_in, off_in, fd_out, off_out, size, flag,)
        }

        #[cfg(all(feature = "fs", feature = "fd"))]
        linkat => [old_dirfd, old_path, new_dirfd, new_path, flags, ..] {
            apply!(syscall_imp::fs::sys_link, old_dirfd, old_path, new_dirfd, new_path, flags)
        }

        #[cfg(all(feature = "fs", target_arch = "x86_64"))]
        unlink => [path_name, flags, ..] {
             apply!(syscall_imp::fs::sys_unlink, path_name, flags)
        }

        #[cfg(all(feature = "fs", feature = "fd"))]
        unlinkat => [dirfd, path_name, flags, ..] {
             apply!(syscall_imp::fs::sys_unlinkat, dirfd, path_name, flags)
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
            validate_ptr!(buf, ctypes::dirent, MappingFlags::WRITE);
            let count:c_int = count.try_into().unwrap();
            apply!(sys_getdents, fd, buf, count)
        }

        #[cfg(all(feature = "fs", feature = "fd"))]
        fstat => [fd, buf, ..] {
            validate_ptr!(buf, test_stat, MappingFlags::WRITE);
            unsafe { apply!(syscall_imp::fs::sys_fstat, fd, buf) }
        }
        statx => [dirfd, path, flags, mask, buf, ..] {
            validate_ptr!(buf, arceos_posix_api::ctype_my::statx, MappingFlags::WRITE);
            unsafe { apply!(syscall_imp::fs::sys_statx, dirfd, path, flags, mask, buf) }
        }
        #[cfg(target_arch = "riscv64")]
        #[cfg(all(feature = "fs", feature = "fd"))]
        fstatat => [dir_fd, pathname, buf, flags, ..] {
            unsafe { apply!(syscall_imp::fs::sys_fstatat, dir_fd, pathname, buf, flags) }
        }
        statfs => [path, buf,..]{
            validate_ptr!(buf, axfs_vfs::structs::FileSystemInfo, MappingFlags::WRITE);
            apply!(fs::sys_statfs, path , buf)
        }
        fgetxattr =>[fd, name, buf, sizes,..]{
            validate_ptr!(buf, c_void, MappingFlags::WRITE);
            apply!(fs::sys_fgetxattr, fd, name ,buf as *mut c_void, sizes)
        }
        fsetxattr =>[fd, name, buf, sizes, flag,..]{
            validate_ptr!(buf, c_void, MappingFlags::WRITE);
            apply!(sys_fsetxattr,fd, name, buf, sizes, flag)
        }
        flistxattr=>[fd,list,size,..]{
            apply!(sys_flistxattr, fd, list, size)
        }
        fremovexattr =>[fd, name,..]{
            apply!(sys_fremovexattr, fd ,name)
        }
        truncate => [path, len, ..]{
            apply!(fs::sys_truncate, path, len)
        }
        ftruncate => [fd, len, ..]{
            apply!(fs::sys_ftruncate, fd, len)
        }
        readlinkat => [dirfd, path, buf, bufsize,..]{
            apply!(fs::sys_readlinkat, dirfd, path, buf, bufsize)
        }
        utimensat =>[dirfd ,path ,times, flags,..]{
            ///Now it can NOT change atime_nec and mtime_nec and support large number like 1LL<<32
            let mut now: timeval = timeval{tv_sec:0, tv_usec:0 };
            sys_get_time_of_day(&mut now).unwrap();
            apply!(sys_utimesat, dirfd, path, times, now, flags)
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
        #[cfg(all(feature = "fs", feature = "fd"))]
        ppoll => [fds, nfds, timeout, sigmask, ..] {
            //validate_ptr!(fds, ctypes::pollfd, nfds, MappingFlags::READ | MappingFlags::WRITE);
            // timeout, sigmask 可选校验
            apply!(syscall_imp::fd::sys_ppoll, fds, nfds, timeout, sigmask)
        }
        #[cfg(feature = "pipe")]
        pipe2 => [fds, ..] {
            let fds = unsafe { core::slice::from_raw_parts_mut(fds as *mut c_int, 2) };
            syscall_imp::pipe::sys_pipe(fds)
        }
        pread64 => [fd, buf_ptr, size, off_t, ..] {
            fs::sys_pread64(fd as c_int, buf_ptr as *mut u8, size, off_t as isize)
        }
        pwrite64 => [fd, buf_ptr, size, off_t,..] {
            fs::sys_pwrite64(fd as c_int, buf_ptr as *mut u8, size, off_t as isize)
        }

        mount => [src, mnt, fstype, mntflag,..]{
            apply!(fs::sys_mount, src, mnt, fstype, mntflag)
        }
        umount2=> [mnt,..]{
            apply!(fs::sys_umount2, mnt)
        }
        // 虚拟内存管理
        brk => [new_heap_top, ..] {
            syscall_imp::mm::sys_brk(new_heap_top)
        }
        mprotect => [addr, size, prot, ..] {
            syscall_imp::mm::sys_mprotect(addr, size, prot)
        }
        mmap => [addr, len, prot, flags, fd, offset, ..] {
            syscall_imp::mm::sys_mmap(addr, len, prot, flags, fd as _, offset)
        }
        munmap => [start, size, ..] {
            syscall_imp::mm::sys_munmap(start, size)
        }

        //信号处理
        rt_sigaction => [signum, act, oldact, ..] {
            syscall_imp::signal::sys_rt_sigaction(signum as i32, act, oldact)
        }
        rt_sigprocmask => [how, set, oldset, ..] {
            syscall_imp::signal::sys_rt_sigprocmask(how as i32, set, oldset)
        }
        rt_sigtimedwait => [set, info, timeout, ..] {
            syscall_imp::signal::sys_rt_sigtimedwait(set, info, timeout)
        }
        rt_sigreturn => _ {
            syscall_imp::signal::sys_rt_sigreturn()
        }
        rt_sigsuspend => [mask_ptr, sigsetsize, ..] {
            syscall_imp::signal::sys_rt_sigsuspend(mask_ptr, sigsetsize)
        }
        // 进程控制相关系统调用
        exit => [code, ..] {
            syscall_imp::process::sys_exit(code as i32)
        }
        exit_group => [code, ..] {
            syscall_imp::process::sys_exit_group(code as i32)
        }
        clone => [flags, sp, parent_tid, a4, a5, ..] {
            syscall_imp::process::sys_clone(flags, sp, parent_tid, a4, a5)
        }
        wait4 => [pid, wstatus, options, ..] {
            syscall_imp::process::sys_wait4(pid as i32, wstatus, options as u32)
        }
        execve => [pathname, argv, envp, ..] {
            syscall_imp::process::sys_execve(pathname, argv, envp)
        }
        set_tid_address => [tidptr, ..] {
            syscall_imp::process::sys_set_tid_address(tidptr)
        }
        getpid => _ {
            syscall_imp::process::sys_getpid()
        }
        gettid => _ {
            syscall_imp::process::sys_gettid()
        }
        getppid => _ {
            syscall_imp::process::sys_getppid()
        }
        getgid => _ {
            syscall_imp::process::sys_getgid()
        }
        getuid => _ {
            syscall_imp::process::sys_getuid()
        }
        geteuid => _ {
            syscall_imp::process::sys_geteuid()
        }
        getegid => _ {
            syscall_imp::process::sys_getegid()
        }
        getpgid => _ {
            Ok(0)
        }
        setpgid => _ {
            Ok(0)
        }
        kill => [pid, sig, ..] {
            syscall_imp::process::sys_kill(pid as i32, sig as u32)
        }
        tkill => [tid, sig, ..] {
            syscall_imp::process::sys_tkill(tid as i32, sig as u32)
        }
        /*
         *tgkill => [tid, sig, ..] {
         *    syscall_imp::process::sys_tgkill(tid as i32, sig as u32)
         *}
         */
        setxattr => _ {
            syscall_imp::process::sys_setxattr()
        }
        sched_yield => _ {
            syscall_imp::task::sys_yield()
        }
        set_robust_list=>[head, size, ..]{
            apply!(syscall_imp::process::sys_set_robust_list, head, size)
        }
        // 时间相关系统调用
        times => [tms_ptr, ..] {
            syscall_imp::time::sys_times(tms_ptr)
        }
        clock_gettime => [clk_id, ts, ..] {
            validate_ptr!(ts, ctypes::timespec, MappingFlags::WRITE);
            apply!(syscall_imp::time::sys_clock_gettime, clk_id, ts)
        }
        clock_gettime64 => args {
            let cls = args[0];
            let ts: *mut ctypes::timespec = args[1] as *mut ctypes::timespec;
            syscall_imp::time::sys_clock_gettime(cls as ctypes::clockid_t, ts)
        }
        gettimeofday => [ts, ..] {
            validate_ptr!(ts, ctypes::timeval, MappingFlags::WRITE);
            apply!(syscall_imp::time::sys_get_time_of_day, ts)
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
        //资源相关系统调用
        getrlimit => [resource, rlimit, ..] {
            validate_ptr!(rlimit, ctypes::rlimit, MappingFlags::WRITE);
            apply!(syscall_imp::source::sys_getrlimit, resource, rlimit)
        }
        setrlimit => [resource, rlimit, ..] {
            validate_ptr!(rlimit, ctypes::rlimit, MappingFlags::READ);
            apply!(syscall_imp::source::sys_setrlimit, resource, rlimit)
        }
        prlimit64 => [pid, resource, new_limit, old_limit, ..] {
            validate_ptr!(new_limit, ctypes::rlimit, MappingFlags::READ, nullable);
            validate_ptr!(old_limit, ctypes::rlimit, MappingFlags::WRITE, nullable);
            apply!(syscall_imp::source::sys_prlimit64, pid, resource, new_limit, old_limit)
        }
        // 其他系统调用
        uname => [buf, ..] apply!(sys_uname, buf),
        ioctl=>_{
            Ok(0)
        }
        sysinfo => [buf, ..] {
            apply!(syscall_imp::sys::sys_sysinfo, buf)
        }
        getrandom => [buf, len, flags, ..] {
            unsafe{sys::sys_getrandom(buf as _, len as _, flags as _)}
        }
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
        sched_getaffinity => _ {
            Ok(0)
        }
        fchown => _ {
            Ok(0)
        }
        fchownat => _ {
            Ok(0)
        }
        fchmod => _ {
            Ok(0)
        }
        fchmodat => _ {
            Ok(0)
        }
        faccessat => _ {
            Ok(0)
        }
        futex => [uaddr, futex_op, val, timeout, uaddr2, val3, ..] {
            error!("exit futex");
            axmono::task::sys_exit(-1 as i32);
            // 调用 syscall/pthread.rs 中实现的 sys_futex
            // pthread::sys_futex(uaddr, futex_op, val, timeout as isize, uaddr2, val3)
            Ok(0)
        }


        // System V IPC Shared Memory System Calls
        // shmget(key, size, shmflg)
        shmget => [key, size, shmflg, ..] {
            apply!(syscall_imp::ipc::sys_shmget, key, size, shmflg)
        }

        // shmat(shmid, shmaddr, shmflg)
        shmat => [shmid, shmaddr, shmflg, ..] {
            // shmid: c_int (i32)
            // shmaddr: *const c_void (usize -> *const c_void)
            // shmflg: c_int (i32)
            // 注意：shmaddr 是一个裸指针，需要从 usize 转换
            let shmaddr_ptr: *const c_void = shmaddr as *const c_void;
            apply!(syscall_imp::ipc::sys_shmat, shmid, shmaddr_ptr, shmflg)
        }

        // shmdt(shmaddr)
        shmdt => [shmaddr, ..] {
            // shmaddr: *const c_void (usize -> *const c_void)
            let shmaddr_ptr: *const c_void = shmaddr as *const c_void;
            apply!(syscall_imp::ipc::sys_shmdt, shmaddr_ptr)
        }

        // shmctl(shmid, cmd, buf)
        shmctl => [shmid, cmd, buf, ..] {
            // shmid: c_int (i32)
            // cmd: c_int (i32)
            // buf: *mut c_void (usize -> *mut c_void)
            // 注意：buf 是一个裸指针，需要从 usize 转换
            let buf_ptr: *mut c_void = buf as *mut c_void;
            apply!(syscall_imp::ipc::sys_shmctl, shmid, cmd, buf_ptr)
        }

        pselect6 => [nfds, readfds, writefds, exceptfds, timeout, sigmask] {
            // 因为 sys_pselect 内部可能需要裸指针操作，所以这里也需要 unsafe
            unsafe {
                apply!(
                    syscall_imp::io::sys_pselect,
                    nfds, readfds, writefds, exceptfds, timeout, sigmask
                )
            }
        }

        capget => [cap_user_header, cap_user_data, ..] {
           Ok(0)
        }
);
