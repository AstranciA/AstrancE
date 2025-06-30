use crate::SyscallResult;
use crate::ToLinuxResult;

#[inline]
pub fn sys_brk(new_heap_top: usize) -> SyscallResult {
    axmono::syscall::mm::sys_brk(new_heap_top)
}

#[inline]
pub fn sys_mprotect(addr: usize, size: usize, prot: usize) -> SyscallResult {
    axmono::syscall::mm::sys_mprotect(addr, size, prot)
}

#[inline]
pub fn sys_mmap(addr: usize, len: usize, prot: usize, flags: usize, fd: i32, offset: usize) -> SyscallResult {
    axmono::syscall::mm::sys_mmap(addr, len, prot, flags, fd, offset)
}

#[inline]
pub fn sys_munmap(start: usize, size: usize) -> SyscallResult {
    axmono::syscall::mm::sys_munmap(start, size)
} 
