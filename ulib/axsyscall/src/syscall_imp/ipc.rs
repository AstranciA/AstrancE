//! System V IPC (Inter-Process Communication) related system calls.

use core::ffi::{c_int, c_void};
use axerrno::{AxError, AxResult, LinuxError, LinuxResult};
use axmono::syscall as api;

/// POSIX `shmget()` system call.
/// Creates or gets a System V shared memory segment.
///
/// `key`: A unique key (IPC_PRIVATE for a new private segment).
/// `size`: The size of the shared memory segment in bytes.
/// `shmflg`: Flags like IPC_CREAT, IPC_EXCL, and permission bits.
///
/// Returns the shared memory ID (shmid) on success, or -1 on error.
pub fn sys_shmget(key: c_int, size: usize, shmflg: c_int) -> LinuxResult<isize> {
    api::ipc::sys_shmget(key, size, shmflg)
}

/// POSIX `shmat()` system call.
/// Attaches a shared memory segment to the calling process's address space.
///
/// `shmid`: The shared memory ID returned by `shmget()`.
/// `shmaddr`: The preferred virtual address to attach (NULL for kernel to choose).
/// `shmflg`: Flags like SHM_RDONLY, SHM_REMAP.
///
/// Returns the virtual address where the segment is attached on success, or -1 on error.
pub fn sys_shmat(shmid: c_int, shmaddr: *const c_void, shmflg: c_int) -> LinuxResult<isize> {
    api::ipc::sys_shmat(shmid, shmaddr, shmflg)
}

/// POSIX `shmdt()` system call.
/// Detaches the shared memory segment located at `shmaddr` from the calling process's address space.
///
/// `shmaddr`: The virtual address where the segment is attached.
///
/// Returns 0 on success, or -1 on error.
pub fn sys_shmdt(shmaddr: *const c_void) -> LinuxResult<isize> {
    api::ipc::sys_shmdt(shmaddr)
}

/// POSIX `shmctl()` system call.
/// Performs control operations on a shared memory segment.
///
/// `shmid`: The shared memory ID.
/// `cmd`: The command to perform (e.g., IPC_RMID, IPC_STAT, IPC_SET).
/// `buf`: Pointer to a `shmid_ds` structure (for IPC_STAT/IPC_SET).
///
/// Returns 0 on success, or -1 on error.
pub fn sys_shmctl(shmid: c_int, cmd: c_int, buf: *mut c_void) -> LinuxResult<isize> {
    api::ipc::sys_shmctl(shmid, cmd, buf)
}
