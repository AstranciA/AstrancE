use alloc::sync::Arc;
use alloc::vec::Vec;
use axerrno::LinuxError;
use axprocess::Pid;
use axsignal::Signal;
use axtask::{current, exit as axtask_exit, TaskExtRef};
use core::ffi::c_int;
use memory_addr::VirtAddr;

use crate::{
    ptr::UserPtr,
    task::{get_process, get_thread, ProcessData, ThreadData, PROCESS_TABLE, THREAD_TABLE},
};

/// Exit the current task (thread).
///
/// This function is called when a task finishes its execution or is terminated.
/// It performs cleanup operations and notifies the parent process if necessary.
pub fn exit_current_task(exit_code: i32) -> ! {
    let curr_task = current();
    let task_ext = curr_task.task_ext();
    let thread = task_ext.thread.clone();
    let process = thread.process();

    debug!(
        "Task {} (PID: {}, TID: {}) exiting with code {}",
        curr_task.name(),
        process.pid(),
        thread.tid(),
        exit_code
    );

    // 1. Handle clear_child_tid
    let clear_child_tid_addr = task_ext.thread_data().clear_child_tid();
    if clear_child_tid_addr != 0 {
        debug!("Clearing child tid at address {:#x}", clear_child_tid_addr);
        let clear_child_tid_ptr: UserPtr<c_int> =
            UserPtr::from_addr(VirtAddr::from(clear_child_tid_addr));
        // Safety: We assume the user pointer is valid within the task's address space.
        // A more robust implementation would verify this.
        if let Ok(_) = clear_child_tid_ptr.write(0) {
            // Wake up the futex at this address
            // TODO: Implement futex wake up
            // sys_futex(clear_child_tid_addr, FUTEX_WAKE, 1, 0, 0, 0);
        } else {
            warn!("Failed to clear child tid at address {:#x}", clear_child_tid_addr);
        }
    }

    // 2. Notify parent process if this is the last thread in a process or a clone child
    let process_data = process.data::<ProcessData>().unwrap();
    let is_clone_child = process_data.is_clone_child();
    let is_last_thread = process.thread_count() == 1;

    if is_last_thread || is_clone_child {
        debug!(
            "Task {} is the last thread ({}) or a clone child ({}), notifying parent",
            curr_task.name(),
            is_last_thread,
            is_clone_child
        );
        // Send SIGCHLD to the parent process
        if let Some(parent) = process.parent() {
            debug!("Sending SIGCHLD to parent process {}", parent.pid());
            parent.data::<ProcessData>().unwrap().send_signal(Signal::SIGCHLD);
            // Wake up parent if it's waiting
            parent.data::<ProcessData>().unwrap().child_exit_wq.wake_all();
        } else {
            // If no parent, maybe it's the init process or an orphaned process
            debug!("Task {} has no parent process", curr_task.name());
        }
    }

    // 3. Handle detached state for pthread
    // Check if the corresponding Pthread struct exists and is marked as detached
    if let Ok(pthread_ptr) = crate::api::arceos_posix_api::sys_pthread_self_raw() {
        if !pthread_ptr.is_null() {
            let pthread = unsafe { &*(pthread_ptr as *const crate::api::arceos_posix_api::imp::pthread::Pthread) };
            if pthread.detached {
                debug!("Detached thread {} exiting, cleaning up resources", thread.tid());
                // TODO: Implement resource cleanup for detached threads
                // This might involve dropping the Pthread struct and associated resources
                // without waiting for pthread_join.
                // For now, we rely on the TaskInner being dropped.
            }
        }
    }


    // 4. Remove thread from global table
    THREAD_TABLE.write().remove(&thread.tid());

    // 5. If this is the last thread of a process, remove the process from the global table
    if is_last_thread {
        debug!("Process {} has no more threads, removing from table", process.pid());
        PROCESS_TABLE.write().remove(&process.pid());
        // TODO: Also remove process group and session if they become empty
    }

    // 6. Exit the axtask::Task
    axtask_exit(exit_code);
}

/// sys_exit
///
/// Terminates the calling process.
///
/// See <https://manpages.debian.org/unstable/manpages-dev/exit.2.en.html>
pub fn sys_exit(exit_code: c_int) -> ! {
    debug!("sys_exit <= {}", exit_code);
    exit_current_task(exit_code);
}

/// sys_exit_group
///
/// Terminates all threads in the calling process's thread group.
///
/// See <https://manpages.debian.org/unstable/manpages-dev/exit_group.2.en.html>
pub fn sys_exit_group(exit_code: c_int) -> ! {
    debug!("sys_exit_group <= {}", exit_code);
    let curr_task = current();
    let process = curr_task.task_ext().thread.process();

    // Iterate over all threads in the process's thread group and exit them
    let threads_to_exit: Vec<Arc<axprocess::Thread>> = process.threads();
    for thread in threads_to_exit {
        if thread.tid() != curr_task.id().as_u64() as Pid {
            // TODO: Signal other threads to exit gracefully
            // For now, we directly exit the task associated with the thread
            if let Ok(task) = axtask::get_task(thread.tid().as_u64()) {
                // This might be unsafe if the task is currently running on another CPU
                // A proper implementation would send a signal or use a dedicated exit mechanism
                warn!("Forcibly exiting thread {} in exit_group", thread.tid());
                task.exit(exit_code);
            }
        }
    }

    // Finally, exit the current task (which will handle the process cleanup if it's the last thread)
    exit_current_task(exit_code);
}

// Helper function to get the raw pthread pointer (for internal use)
// This avoids exposing the internal Pthread struct directly in the API
pub(crate) fn sys_pthread_self_raw() -> LinuxResult<*mut core::ffi::c_void> {
    let tid = current().id().as_u64();
    THREAD_TABLE.read().get(&tid).map(|weak_thread| {
        weak_thread.upgrade().map(|thread| {
            // Assuming Pthread struct is stored in TaskExt
            let task = axtask::get_task(tid).unwrap(); // Get the task by tid
            let task_ext = task.task_ext();
            // This is a placeholder. The actual Pthread pointer needs to be stored and retrieved.
            // For now, we'll try to find it in the TID_TO_PTHREAD map in arceos_posix_api
            let pthread_map = crate::api::arceos_posix_api::imp::pthread::TID_TO_PTHREAD.read();
            pthread_map.get(&tid).map(|force_send_sync_ptr| force_send_sync_ptr.0).unwrap_or(core::ptr::null_mut())
        }).unwrap_or(core::ptr::null_mut())
    }).ok_or(LinuxError::ESRCH)
}
