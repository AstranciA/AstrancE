//! System V IPC (Inter-Process Communication) related system calls.

use core::ffi::{c_int, c_void};

use arceos_posix_api::{ctypes, syscall_body}; // Note: syscall_body might not be needed after this change
use axerrno::{AxError, AxResult, LinuxError};
use axhal::mem::VirtAddr;
use axlog::{debug, error};
use axmm::{
    AddrSpace, MmapFlags, MmapPerm,
    shm::{
        IPC_CREAT, IPC_EXCL, IPC_PRIVATE, IPC_RMID, ShmError, shm_at as axmm_shm_at,
        shm_ctl as axmm_shm_ctl, shm_dt as axmm_shm_dt, shm_get as axmm_shm_get,
    },
};
use axsyscall::SyscallResult; // Assuming SyscallResult is Result<isize, LinuxError>
use axtask::{TaskExtRef, current}; // Import debug and error for logging

/// POSIX `shmget()` system call.
/// Creates or gets a System V shared memory segment.
///
/// `key`: A unique key (IPC_PRIVATE for a new private segment).
/// `size`: The size of the shared memory segment in bytes.
/// `shmflg`: Flags like IPC_CREAT, IPC_EXCL, and permission bits.
///
/// Returns the shared memory ID (shmid) on success, or -1 on error.
pub fn sys_shmget(key: c_int, size: usize, shmflg: c_int) -> SyscallResult {
    debug!(
        "sys_shmget <= key:{} size:{} shmflg:{:#o}",
        key, size, shmflg
    );
    // Extract permission bits from shmflg (e.g., 0o666)
    // In this simplified version without IpcPerm, we just pass shmflg directly.
    // A real implementation would parse and use these for permission checks.

    axmm_shm_get(key, size, shmflg)
        .map(|shm| shm.lock().id as isize) // Return shmid as isize
        .map_err(LinuxError::from) // Convert AxError to LinuxError
}

/// POSIX `shmat()` system call.
/// Attaches a shared memory segment to the calling process's address space.
///
/// `shmid`: The shared memory ID returned by `shmget()`.
/// `shmaddr`: The preferred virtual address to attach (NULL for kernel to choose).
/// `shmflg`: Flags like SHM_RDONLY, SHM_REMAP.
///
/// Returns the virtual address where the segment is attached on success, or -1 on error.
pub fn sys_shmat(shmid: c_int, shmaddr: *const c_void, shmflg: c_int) -> SyscallResult {
    debug!(
        "sys_shmat <= shmid:{} shmaddr:{:#x} shmflg:{:#o}",
        shmid, shmaddr as usize, shmflg
    );

    let manager = axmm::shm::SHM_MANAGER.lock(); // Access global SHM manager
    let shm_segment_arc = manager
        .get(&(shmid as usize))
        .map(|s| s.clone())
        .ok_or(LinuxError::EINVAL)?; // shmid invalid or not found
    drop(manager); // Release manager lock early

    let curr = current();
    let mut aspace = curr.task_ext().process_data().aspace.lock(); // Get current process's address space

    axmm_shm_at(shm_segment_arc, shmaddr as usize, shmflg, &mut aspace)
        .map(|vaddr| vaddr.as_usize() as isize) // Return virtual address as isize
        .inspect_err(|e| {
            warn!("{e:?}");
            panic!()
        })
        .map_err(LinuxError::from)
}

/// POSIX `shmdt()` system call.
/// Detaches the shared memory segment located at `shmaddr` from the calling process's address space.
///
/// `shmaddr`: The virtual address where the segment is attached.
///
/// Returns 0 on success, or -1 on error.
pub fn sys_shmdt(shmaddr: *const c_void) -> SyscallResult {
    debug!("sys_shmdt <= shmaddr:{:#x}", shmaddr as usize);

    let curr = current();
    let mut aspace = curr.task_ext().process_data().aspace.lock(); // Get current process's address space

    axmm_shm_dt((shmaddr as usize).into(), &mut aspace)
        .map(|_| 0 as isize) // Return 0 on success
        .map_err(LinuxError::from)
}

/// POSIX `shmctl()` system call.
/// Performs control operations on a shared memory segment.
///
/// `shmid`: The shared memory ID.
/// `cmd`: The command to perform (e.g., IPC_RMID, IPC_STAT, IPC_SET).
/// `buf`: Pointer to a `shmid_ds` structure (for IPC_STAT/IPC_SET).
///
/// Returns 0 on success, or -1 on error.
pub fn sys_shmctl(shmid: c_int, cmd: c_int, buf: *mut c_void) -> SyscallResult {
    debug!(
        "sys_shmctl <= shmid:{} cmd:{} buf:{:#x}",
        shmid, cmd, buf as usize
    );

    axmm_shm_ctl(shmid as usize, cmd, buf as usize)
        .map(|_| 0 as isize) // Return 0 on success
        .map_err(LinuxError::from)
}
