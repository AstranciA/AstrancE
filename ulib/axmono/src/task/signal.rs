use core::{ffi::c_int, time::Duration};

use alloc::sync::Arc;
//use arceos_posix_api::ctypes::{self, *};
use axerrno::{LinuxError, LinuxResult, ax_err};
use axprocess::Pid;
use axhal::{arch::TrapFrame, time::monotonic_time};
use axsignal::*;
use axsync::Mutex;
use axtask::{TaskExtRef, current, exit, yield_now};
use linux_raw_sys::general::*;
use memory_addr::VirtAddr;

use crate::{
    mm::trampoline_vaddr,
    ptr::{PtrWrapper, UserPtr},
    task::PROCESS_GROUP_TABLE,
};

use super::{
    PROCESS_TABLE, ProcessData, THREAD_TABLE, time::TimeStat, time_stat_from_old_task,
    time_stat_to_new_task, write_trapframe_to_kstack, yield_with_time_stat,
};

pub fn default_signal_handler(signal: Signal, ctx: &mut SignalContext) {
    match signal {
        Signal::SIGINT | Signal::SIGKILL => {
            // 杀死进程
            let curr = current();
            debug!("kill myself");
            exit(curr.task_ext().thread.process().exit_code());
        }
        _ => {
            // 忽略信号
            debug!("Ignoring signal: {:?}", signal)
        }
    }
}

pub fn spawn_signal_ctx() -> Arc<Mutex<SignalContext>> {
    let mut ctx = SignalContext::default();
    ctx.set_action(Signal::SIGKILL, SigAction {
        handler: SigHandler::Default(default_signal_handler),
        mask: SignalSet::SIGKILL,
        flags: SigFlags::empty(),
    });
    ctx.set_action(Signal::SIGINT, SigAction {
        handler: SigHandler::Default(default_signal_handler),
        mask: SignalSet::SIGINT,
        flags: SigFlags::empty(),
    });

    Arc::new(Mutex::new(ctx))
}

pub(crate) fn sys_sigaction(
    signum: c_int,
    act: *const sigaction,
    old_act: *mut sigaction,
) -> LinuxResult<isize> {
    let sig: Signal = signum.try_into()?;
    let curr = current();
    // Signal actions are process-wide
    let mut sigctx = curr.task_ext().process_data().signal.lock();
    if !act.is_null() {
        let act = SigAction::try_from(unsafe { *act }).inspect_err(|e| {})?;
        let old = sigctx.set_action(sig, act);
        // 设置旧动作（如果有）
        unsafe { old_act.as_mut().map(|ptr| unsafe { *ptr = old.into() }) };
    } else {
        // 只获取旧动作（如果有）
        unsafe {
            let old = sigctx.get_action(sig);
            old_act
                .as_mut()
                .map(|ptr| unsafe { *ptr = (*sigctx.get_action(sig)).into() });
        };
    }

    Ok(0)
}

pub(crate) fn sys_sigprocmask(
    how: c_int,
    set: *const sigset_t,
    oldset: *mut sigset_t,
) -> LinuxResult<isize> {
    let curr = current();
    // Signal mask is thread-specific
    let mut thread_sigmask = curr.task_ext().thread_data().signal_mask.lock();

    if !oldset.is_null() {
        unsafe {
            oldset
                .as_mut()
                .map(|ptr| unsafe { *ptr }.sig[0] = thread_sigmask.bits())
        };
    }

    if !set.is_null() {
        let set: SignalSet = unsafe { *set }.into();

        match how as u32 {
            SIG_BLOCK => *thread_sigmask = thread_sigmask.union(set),
            SIG_UNBLOCK => *thread_sigmask = thread_sigmask.difference(set),
            SIG_SETMASK => *thread_sigmask = set,
            _ => return Err(LinuxError::EINVAL),
        };
    }

    Ok(0)
}

pub(crate) fn sys_kill(pid: c_int, sig: c_int) -> LinuxResult<isize> {
    let signal = Signal::from_u32(sig as _).ok_or(LinuxError::EINVAL)?;
    if pid > 0 {
        // Send signal to a specific process
        let target_pid = pid as Pid;
        let process = PROCESS_TABLE
            .read()
            .get(&target_pid)
            .ok_or(LinuxError::ESRCH)?;
        let data: &ProcessData = process.data().ok_or_else(|| {
            error!("Process {} has no data", pid);
            LinuxError::EFAULT
        })?;
        // Add signal to the process's pending signal set
        data.signal.lock().send_signal(signal.into());
        // TODO: Wake up a thread in the process that can handle the signal
        // This requires finding a thread whose signal mask does not block the signal
        // and waking it up if it's waiting (e.g., in sigtimedwait or sigsuspend).
    } else {
        warn!("Not supported yet: pid: {:?}", pid);
        return Err(LinuxError::EINVAL);
    }
    Ok(0)
}

pub(crate) fn sys_sigtimedwait(
    sigset_ptr: *const sigset_t,
    info: *mut siginfo_t,
    timeout_ptr: *const timespec,
) -> LinuxResult<isize> {
    let wait_set: SignalSet = unsafe { *(sigset_ptr.as_ref().ok_or(LinuxError::EFAULT)?) }.into();
    let curr = current();
    let start_time = monotonic_time();

    // Check for timeout
    let has_timeout = !timeout_ptr.is_null();
    let timeout_duration = if has_timeout {
        let ts = unsafe { timeout_ptr.as_ref().ok_or(LinuxError::EFAULT)? };
        if ts.tv_sec == 0 && ts.tv_nsec == 0 {
            // Special case: immediate return
            let mut process_sigctx = curr.task_ext().process_data().signal.lock();
            let thread_sigmask = curr.task_ext().thread_data().signal_mask.lock();
            // Check pending signals that are not blocked by the thread's mask
            if let Some(sig) = process_sigctx.take_pending_in(wait_set.difference(*thread_sigmask)) {
                debug!("Received signal immediately: {:?}", sig);
                return Ok(sig as isize);
            } else {
                return Err(LinuxError::EAGAIN);
            }
        }
        Some(Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32))
    } else {
        None
    };

    // Main waiting loop
    loop {
        let mut process_sigctx = curr.task_ext().process_data().signal.lock();
        let thread_sigmask = curr.task_ext().thread_data().signal_mask.lock();

        // Check for pending signals that are not blocked by the thread's mask
        if let Some(sig) = process_sigctx.take_pending_in(wait_set.difference(*thread_sigmask)) {
            debug!("Received signal after waiting: {:?}", sig);
            // TODO: Populate siginfo structure if info is not null
            return Ok(sig as isize);
        }

        // Check timeout
        if let Some(duration) = timeout_duration {
            let elapsed = monotonic_time() - start_time;
            if elapsed >= duration {
                return Err(LinuxError::EAGAIN);
            }
        }

        // Yield CPU
        drop(process_sigctx); // Release lock before yielding
        drop(thread_sigmask); // Release lock before yielding
        yield_with_time_stat();
    }
}

pub(crate) fn sys_rt_sigsuspend(mask_ptr: *const sigset_t, sigsetsize: usize) -> LinuxResult<isize> {
    // 1. Validate signal set size
    if sigsetsize != core::mem::size_of::<sigset_t>() {
        return Err(LinuxError::EINVAL);
    }
    // 2. Read new signal mask from user space
    let new_mask: SignalSet = unsafe {
        let mask_ref = mask_ptr.as_ref().ok_or(LinuxError::EFAULT)?;
        (*mask_ref).into()
    };
    // 3. Get current task and thread-specific signal mask
    let curr = current();
    let mut thread_sigmask = curr.task_ext().thread_data().signal_mask.lock();
    // 4. Save the current thread signal mask and set the new one
    let old_mask = *thread_sigmask;
    *thread_sigmask = new_mask;
    // 5. Suspend the thread, waiting for a signal
    loop {
        let process_sigctx = curr.task_ext().process_data().signal.lock();
        let thread_sigmask_current = curr.task_ext().thread_data().signal_mask.lock();

        // Check for pending signals that are not blocked by the *current* thread's mask
        if process_sigctx.has_pending_in(SignalSet::all().difference(*thread_sigmask_current)) {
            // If there is a pending signal that is not blocked, the signal handler will be invoked
            // upon returning to user space. sigsuspend should be interrupted by *any* signal
            // whose action is to invoke a handler or terminate the process.
            // Upon return from the signal handler (via sigreturn), the original signal mask
            // (old_mask) will be restored.
            // sigsuspend always returns -1 with errno set to EINTR.
            // We don't restore the mask here, as it's done by sigreturn.
            return Err(LinuxError::EINTR);
        }
        // Yield CPU, enter waiting state
        drop(process_sigctx); // Release lock before yielding
        drop(thread_sigmask_current); // Release lock before yielding
        yield_with_time_stat();
    }
}


pub(crate) fn handle_pending_signals(current_tf: &TrapFrame) {
    let curr = current();
    let process_data = curr.task_ext().process_data();
    let mut process_sigctx = process_data.signal.lock();
    let mut thread_sigmask = curr.task_ext().thread_data().signal_mask.lock();

    // Check for pending signals that are not blocked by the current thread's mask
    if !process_sigctx.has_pending_in(SignalSet::all().difference(*thread_sigmask)) {
        return;
    }

    // Unlock signal contexts before calling axsignal::handle_pending_signals
    // as it might yield or exit.
    drop(process_sigctx);
    drop(thread_sigmask);

    // Re-acquire mutable references
    let process_data_mut = curr.task_ext().process_data();
    let mut process_sigctx_mut = process_data_mut.signal.lock();
    let mut thread_sigmask_mut = curr.task_ext().thread_data().signal_mask.lock();


    // Call axsignal::handle_pending_signals with the process's signal context
    // and the thread's signal mask.
    match axsignal::handle_pending_signals(&mut process_sigctx_mut, &mut thread_sigmask_mut, current_tf, unsafe {
        trampoline_vaddr(sigreturn_trampoline as usize).into()
    }) {
        Ok(Some((mut uctx, kstack_top))) => {
            // Exchange trap frame to enter signal handler
            unsafe { write_trapframe_to_kstack(curr.get_kernel_stack_top().unwrap(), &uctx.0) };
        }
        Ok(None) => {
            // No signal handled
        }
        Err(e) => {
            error!("Error handling pending signals: {:?}", e);
            // TODO: Handle signal delivery error (e.g., terminate process)
        }
    };
}

pub(crate) fn sys_sigreturn(tf: &mut TrapFrame) -> LinuxResult<isize> {
    debug!("sys_sigreturn");
    let curr = current();
    let process_data = curr.task_ext().process_data();
    let mut process_sigctx = process_data.signal.lock();
    let mut thread_sigmask = curr.task_ext().thread_data().signal_mask.lock();

    // Unload the signal frame and get the saved context and original signal mask
    // The unload function in axsignal::SignalContext should handle restoring the
    // process-wide blocked mask that was saved in the SignalFrameData.
    let (signal_frame_data, sscratch) = process_sigctx.unload().unwrap();

    // Restore the thread's signal mask to the value it had before the signal handler was invoked.
    // This mask is saved in the SignalFrameData.
    *thread_sigmask = signal_frame_data.uc_sigmask;

    // Restore the trap frame from the signal frame
    // The unload function should return the original trap frame.
    let mut restored_tf = signal_frame_data.orig_frame;

    // Exchange back to the original trap frame
    unsafe { write_trapframe_to_kstack(curr.get_kernel_stack_top().unwrap(), &restored_tf) };
    unsafe { axhal::arch::exchange_trap_frame(sscratch) };

    debug!("sigreturn finished");
    // The return value of sigreturn is typically the result of the interrupted syscall,
    // which is stored in the restored trap frame's return register (e.g., a0 on RISC-V).
    Ok(restored_tf.arg0() as isize)
}

// Helper function to check for pending signals that are not blocked by a given mask
// This is now a method of SignalContext in axsignal crate.
/*
impl SignalContext {
    pub fn has_pending_in(&self, mask: SignalSet) -> bool {
        !self.pending.intersection(mask).is_empty()
    }

    // Helper function to take a pending signal that is not blocked by a given mask
    pub fn take_pending_in(&mut self, mask: SignalSet) -> Option<Signal> {
        self.pending.take_one_in(mask)
    }

    // Helper function to wait for a signal in a given set that is not blocked by a given mask
    // This is a simplified version and needs proper blocking/waiting mechanism.
    pub fn wait_for_signal(&mut self, wait_set: SignalSet, timeout_ns: Option<u64>) -> LinuxResult<Signal> {
        let start_time = monotonic_time();
        loop {
            let thread_sigmask = current().task_ext().thread_data().signal_mask.lock();
            if let Some(sig) = self.take_pending_in(wait_set.difference(*thread_sigmask)) {
                return Ok(sig);
            }
            if let Some(timeout) = timeout_ns {
                if monotonic_time() - start_time >= timeout {
                    return Err(LinuxError::EAGAIN);
                }
            }
            // Release locks before yielding
            drop(thread_sigmask);
            drop(self); // Temporarily drop self to release the lock
            yield_with_time_stat();
            // Re-acquire lock
            let curr = current();
            let process_data = curr.task_ext().process_data();
            // This re-acquisition is problematic in a real multi-threaded scenario.
            // A proper waiting mechanism (like a WaitQueue) should be used here.
            // For now, we'll just re-acquire the mutex.
            // TODO: Replace this with a proper blocking mechanism.
            unsafe {
                 // This is a hack to re-acquire the mutex. Do not use in production code.
                 // A proper solution involves using a WaitQueue or similar synchronization primitive.
                 let process_sigctx_ptr = process_data.signal.as_ref() as *const Mutex<SignalContext>;
                 self = unsafe { &mut *(process_sigctx_ptr as *mut SignalContext) };
            }
        }
    }
}
*/
