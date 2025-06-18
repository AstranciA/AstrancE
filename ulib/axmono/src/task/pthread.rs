use core::ffi::{c_void, c_int};
use axerrno::{LinuxResult, LinuxError};
use crate::ctypes::CloneFlags;
use memory_addr::VirtAddr;
use alloc::vec::Vec;
use alloc::boxed::Box;
use core::ptr;
use axsyscall::apply; // 导入 apply 函数
use syscalls::Sysno;
use axtask::exit;
// 导入 Sysno 枚举
use super::{clone_task};
// 简化的 pthread_t 类型，使用 TaskId 作为线程 ID
pub type pthread_t = usize;

#[repr(C)]
pub struct pthread_attr_t {
    // 线程属性，例如栈大小等
    stack_size: usize,
    // ... 其他属性
}

impl Default for pthread_attr_t {
    fn default() -> Self {
        Self {
            stack_size: 0x8000, // 默认栈大小
        }
    }
}

// 线程入口函数的包装器
extern "C" fn thread_start_wrapper(arg: *mut c_void) {
    // 恢复原始的入口函数和参数
    let (start_routine, original_arg): (extern "C" fn(*mut c_void) -> *mut c_void, *mut c_void) =
        unsafe { Box::from_raw(arg as *mut (extern "C" fn(*mut c_void) -> *mut c_void, *mut c_void)).into() };

    // 调用原始的入口函数
    let ret_val = start_routine(original_arg);

    // 线程退出，调用 pthread_exit
    pthread_exit(ret_val);
}

// 实现 pthread_create
#[no_mangle]
pub extern "C" fn pthread_create(
    thread: *mut pthread_t,
    attr: *const pthread_attr_t,
    start_routine: extern "C" fn(*mut c_void) -> *mut c_void,
    arg: *mut c_void,
) -> c_int {
    // TODO: 根据 attr 处理线程属性

    // 分配线程栈
    // TODO: 需要实现用户空间内存分配，这里简化处理
    let stack_size = unsafe { attr.as_ref().map_or(0x8000, |a| a.stack_size) };
    // 简化处理，假设栈从某个固定地址开始分配
    // 实际应该从进程的堆空间分配
    let stack_base = VirtAddr::from_usize(0x5000_0000); // 示例地址，需要确保不冲突
    let stack_top = stack_base + stack_size;

    // 包装入口函数和参数
    let wrapped_arg = Box::into_raw(Box::new((start_routine, arg))) as *mut c_void;

    // 调用 clone 系统调用创建线程
    let flags = CloneFlags::THREAD | CloneFlags::VM | CloneFlags::FILES | CloneFlags::SIGHAND | CloneFlags::CHILD_CLEARTID;
    let mut child_tid: i32 = 0;
    let child_tid_ptr: *mut i32 = &mut child_tid;
    //TODO syscall there
    let result = unsafe {
        apply!(
            Sysno::clone,
            &[
                flags.bits() as usize,
                stack_top.as_usize(), // 新线程栈顶
                0, // ptid (暂时不设置)
                child_tid_ptr as usize, // ctid
                0, // tls (暂时不设置)
                thread_start_wrapper as usize, // 新线程的入口函数
                wrapped_arg as usize // 新线程的参数
            ]
        )
    };

    match result {
        Ok(tid) => {
            unsafe {
                *thread = tid as pthread_t;
            }
            0 // 成功返回 0
        }
        Err(err) => {
            // TODO: 根据错误类型返回相应的 errno
            -1 // 失败返回 -1
        }
    }
}

// 实现 pthread_join
#[no_mangle]
pub extern "C" fn pthread_join(
    thread: pthread_t,
    retval: *mut *mut c_void,
) -> c_int {
    // pthread_join 实际上是等待指定的线程退出
    // 可以通过 wait4 系统调用等待指定 tid 的任务退出
    let mut status: i32 = 0;
    //TODO syscall there
    let result = unsafe {
        apply(
            Sysno::wait4,
            &[
                thread as isize as usize, // 等待指定的 tid
                &mut status as *mut i32 as usize,
                0, // options
                0 // rusage
            ]
        )
    };

    match result {
        Ok(_) => {
            // TODO: 获取线程的返回值并设置到 retval
            if !retval.is_null() {
                // 假设线程退出码就是返回值
                unsafe {
                    *retval = status as *mut c_void;
                }
            }
            0 // 成功返回 0
        }
        Err(err) => {
            // TODO: 根据错误类型返回相应的 errno
            -1 // 失败返回 -1
        }
    }
}


#[no_mangle]
pub extern "C" fn pthread_exit(retval: *mut c_void) -> ! {
    // 调用 exit 系统调用退出当前线程
    let exit_code = retval as isize; // 简化的退出码处理
    unsafe {
        exit(exit_code as i32);
    }

}

// TODO: 互斥锁、条件变量
