//! syscall impl for AstrancE
mod test;

use syscalls::Sysno;
/// sysno参考[参考文件](file:///root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/syscall_imp-0.6.18/src/arch/riscv64.rs)
// 声明 axsyscalls 模块
// 声明 syscall_imp 模块（对应 syscall_imp 目录）
mod syscall_imp;
use core::ffi::*;
use arceos_posix_api::ctypes;
pub fn syscall_handler(sys_id: usize, args: [usize; 6]) -> Result<isize,isize> {
    let sys_id = Sysno::from(sys_id as u32);//检查id与测例是否适配

    let ret = match sys_id {
        Sysno::write => {
            let fd = args[0];
            let buf_ptr = args[1];
            let size = args[2];
            let buf = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, size) };
            if size == 0 {
                return Err(-1);
            } else {
                syscall_imp::io::ax_write(fd, buf)
            }
        }
        Sysno::read => {
            let fd = args[0];
            let buf_ptr = args[1];
            let size = args[2];
            let buf = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, size) };
            if size == 0 {
                return Err(-1);
            } else {
                syscall_imp::io::ax_read(fd, buf)
            }
        }
        // 文件操作相关系统调用
        Sysno::openat => {
            let dirfd = args[0];//类型检查与转化！
            let fname = args[1];
            let flages = args[2];
            let mode = args[3];
            todo!()
        }
        Sysno::close => {
            todo!()
        }
        Sysno::statfs => {
            todo!()
        }
        Sysno::fstat => {
            todo!()
        }
        Sysno::lseek => {
            let fd = args[0] as c_int;
            let offset = args[1] as ctypes::off_t;
            let whence = args[2] as c_int;
            let ret = syscall_imp::fs::ax_lseek(fd, offset, whence);
            todo!()
        }
        Sysno::mmap => {
            todo!()
        }
        Sysno::munmap => {
            todo!()
        }
        
        // 进程控制相关系统调用
        Sysno::exit => {
            let code = args[0] as c_int;
            syscall_imp::task::ax_exit(code)
        }
        Sysno::getpid => {
            syscall_imp::task::ax_getpid()
        }
        Sysno::clone => {
            todo!()
        }
        Sysno::execve => {
            todo!()
        }
        Sysno::wait4 => {
            todo!()
        }
        Sysno::sched_yield => {
            syscall_imp::task::ax_yield()
        }
        // 时间相关系统调用
        Sysno::clock_gettime => {
            let cls = args[0];
            let ts: *mut ctypes::timespec= args[1] as *mut ctypes::timespec;
            syscall_imp::time::ax_clock_gettime(cls as ctypes::clockid_t, ts)
        }
        Sysno::gettimeofday => {
            let ts: *mut ctypes::timeval= args[0] as *mut ctypes::timeval;
            syscall_imp::time::ax_get_time_of_day(ts)
        }
        Sysno::nanosleep => {
            let req : *const ctypes::timespec = args[0] as *const ctypes::timespec;
            let rem: *mut ctypes::timespec = args[1] as *mut ctypes::timespec;
            syscall_imp::time::ax_nanosleep(req, rem)
        }
        
        // 其他系统调用
        Sysno::brk => {
            todo!()
        }
        Sysno::uname => {
            todo!()
        }
        Sysno::getcwd => {
            todo!()
        }
        Sysno::dup => {
            todo!()
        }
        Sysno::dup3 => {
            todo!()
        }
        Sysno::chdir => {
            todo!()
        }
        Sysno::mkdirat => {
            todo!()
        }
        Sysno::getdents64 => {
            todo!()
        }

        //网络相关
        Sysno::socket => {
            let domain = args[0] as c_int;
            let socktype = args[1] as c_int;
            let protocol = args[2] as c_int;
            syscall_imp::net::ax_socket(domain, socktype, protocol)
        }

        Sysno::bind => {
            let fd = args[0] as c_int;
            let addr = args[1] as *const ctypes::sockaddr;
            let addrlen = args[2] as ctypes::socklen_t;
            syscall_imp::net::ax_bind(fd, addr, addrlen)
        }

        // fd, addr, addrlen
        Sysno::connect => {
            let fd = args[0] as c_int;
            let addr = args[1] as *const ctypes::sockaddr;
            let addrlen = args[2] as ctypes::socklen_t;
            syscall_imp::net::ax_connect(fd, addr, addrlen)
        }

        // fd, buf, len, flags, addr, addrlen
        Sysno::sendto => {
            let fd = args[0] as c_int;
            let buf = args[1] as *const c_void;
            let len = args[2] as usize;
            let flags = args[3] as c_int;
            let addr = args[4] as *const ctypes::sockaddr;
            let addrlen = args[5] as ctypes::socklen_t;
            syscall_imp::net::ax_sendto(fd, buf, len, flags, addr, addrlen)
        }

        // fd, buf, len, flags
        Sysno::sendmsg => {
            let fd = args[0] as c_int;
            let buf = args[1] as *const c_void;
            let len = args[2] as usize;
            let flags = args[3] as c_int;
            syscall_imp::net::ax_send(fd, buf, len, flags)
        }

        // fd, buf, len, flags, addr, addrlen
        Sysno::recvfrom => {
            let fd = args[0] as c_int;
            let buf = args[1] as *mut c_void;
            let len = args[2] as usize;
            let flags = args[3] as c_int;
            let addr = args[4] as *mut ctypes::sockaddr;
            let addrlen = args[5] as *mut ctypes::socklen_t;
            unsafe { syscall_imp::net::ax_recvfrom(fd, buf, len, flags, addr, addrlen) }
        }

        // fd, buf, len, flags
        Sysno::recvmsg => {
            let fd = args[0] as c_int;
            let buf = args[1] as *mut c_void;
            let len = args[2] as usize;
            let flags = args[3] as c_int;
            syscall_imp::net::ax_recv(fd, buf, len, flags)
        }

        // fd, backlog
        Sysno::listen => {
            let fd = args[0] as c_int;
            let backlog = args[1] as c_int;
            syscall_imp::net::ax_listen(fd, backlog)
        }

        // fd, addr, addrlen
        Sysno::accept => {
            let fd = args[0] as c_int;
            let addr = args[1] as *mut ctypes::sockaddr;
            let addrlen = args[2] as *mut ctypes::socklen_t;
            unsafe { syscall_imp::net::ax_accept(fd, addr, addrlen) }
        }

        // fd, how
        Sysno::shutdown => {
            let fd = args[0] as c_int;
            let how = args[1] as c_int;
            syscall_imp::net::ax_shutdown(fd, how)
        }
        
        // fd, addr, addrlen
        Sysno::getsockname => {
            let fd = args[0] as c_int;
            let addr = args[1] as *mut ctypes::sockaddr;
            let addrlen = args[2] as *mut ctypes::socklen_t;
            unsafe { syscall_imp::net::ax_getsockname(fd, addr, addrlen) }
        }

        // fd, addr, addrlen
        Sysno::getpeername => {
            let fd = args[0] as c_int;
            let addr = args[1] as *mut ctypes::sockaddr;
            let addrlen = args[2] as *mut ctypes::socklen_t;
            unsafe { syscall_imp::net::ax_getpeername(fd, addr, addrlen) }
        }

        _ => {
            Err(-1) // Return error code for unsupported syscall_imp
        }
    };

    ret
}

