use core::time::Duration;

use crate::pthread::{FutexFlags, FutexOp, futex};
use arceos_posix_api::ctypes;
// 导入 futex 函数和 FutexOp 枚举
use axerrno::{LinuxError, LinuxResult};
use axsyscall::SyscallResult;
use bitflags::Flags;
use memory_addr::VirtAddr;

/// futex 系统调用的入口点
/// 参数与 Linux 的 futex 系统调用保持一致
/// int futex(int *uaddr, int futex_op, int val, const struct timespec *timeout, int *uaddr2, int val3);
pub fn sys_futex(
    uaddr: usize,
    futex_op: usize,
    val: usize,
    timeout_ptr: isize, // 指向 timespec 结构体
    _uaddr2: usize,
    _val3: usize,
) -> SyscallResult {
    let vaddr = VirtAddr::from(uaddr);
    let flags = FutexFlags::from_bits_truncate(futex_op);
    let op = FutexOp::try_from(futex_op)?;
    let val_u32 = val as u32;
    warn!("{op:?}{flags:?}");

    let timeout: Option<Duration> = if op == FutexOp::Wait && timeout_ptr > 0 {
        let timespec = unsafe { *(timeout_ptr as *const ctypes::timespec) };
        Some(Duration::from(timespec))
    } else {
        None // 无限期等待
    };

    // 调用 pthread/mod.rs 中实现的 futex 逻辑
    futex(vaddr, op, val_u32, flags, timeout).map(|_| 0)
}

// 示例的 sys_pthread 函数，如果不需要可以删除或修改
pub fn sys_pthread(_arg: usize) -> SyscallResult {
    // 这是一个占位符，如果你的 pthread 系统调用有其他功能，可以在这里实现
    Err(LinuxError::ENOSYS) // Not implemented
}
