use core::{ffi::c_int, time::Duration};

use alloc::sync::Arc;
//use arceos_posix_api::ctypes::{self, *};
use axerrno::{LinuxError, LinuxResult, ax_err};
use axhal::{arch::TrapFrame, time::monotonic_time};
use axsignal::*;
use axsync::Mutex;
use axtask::{TaskExtRef, current, exit, yield_now};
use linux_raw_sys::general::*;
use memory_addr::{VirtAddr, VirtAddrRange};

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

// pub(crate) fn sys_sigprocmask(
//     how: c_int,
//     set: *const sigset_t,
//     oldset: *mut sigset_t,
// ) -> LinuxResult<isize> {
//     let curr = current();
//     let mut sigctx = curr.task_ext().process_data().signal.lock();
// 
//     if !set.is_null() {
//         let set: SignalSet = unsafe { *set }.into();
// 
//         let old = match how as u32 {
//             SIG_BLOCK => sigctx.block(set),
//             SIG_UNBLOCK => sigctx.unblock(set),
//             SIG_SETMASK => sigctx.set_mask(set),
//             _ => return Err(LinuxError::EINVAL),
//         };
//         unsafe {
//             oldset
//                 .as_mut()
//                 .map(|ptr| unsafe { *ptr }.sig[0] = old.bits())
//         };
//     }
// 
//     Ok(0)
// }

pub(crate) fn sys_sigprocmask(
    how: c_int,
    set: *const sigset_t,
    oldset: *mut sigset_t,
) -> LinuxResult<isize> {
    let curr = current();
    let mut sigctx = curr.task_ext().process_data().signal.lock();

    // 先保存旧的 mask
    let old_mask = sigctx.get_blocked();

    // 如果 set 非 null，则根据 how 修改 mask
    if !set.is_null() {
        let set: SignalSet = unsafe { *set }.into();
        match how as u32 {
            SIG_BLOCK => sigctx.block(set),
            SIG_UNBLOCK => sigctx.unblock(set),
            SIG_SETMASK => sigctx.set_mask(set),
            _ => return Err(LinuxError::EINVAL),
        };
    }

    // 如果用户请求 oldset，则写入旧的 mask
    if !oldset.is_null() {
        unsafe {
            (*oldset).sig[0] = old_mask.bits();
        }
    }

    Ok(0)
}

pub(crate) fn sys_kill(pid: c_int, sig: c_int) -> LinuxResult<isize> {
    let sig = Signal::from_u32(sig as _).ok_or(LinuxError::EINVAL)?;
    if pid > 0 {
        let process = PROCESS_TABLE
            .read()
            .get(&(pid as _))
            .ok_or(LinuxError::ESRCH)?;
        let data: &ProcessData = process.data().ok_or_else(|| {
            error!("Process {} has no data", pid);
            LinuxError::EFAULT
        })?;
        data.send_signal(sig);
    } else {
        warn!("Not supported yet: pid: {:?}", pid);
        return Err(LinuxError::EINVAL);
    }
    Ok(0)
}

pub(crate) fn sys_sigtimedwait(
    sigset: *const sigset_t,
    info: *mut siginfo_t,
    timeout: *const timespec,
) -> LinuxResult<isize> {
    let sigset: SignalSet = unsafe { *(sigset.as_ref().ok_or(LinuxError::EFAULT)?) }.into();
    let curr = current();
    let start_time = monotonic_time();

    // 检查是否有超时设置
    let has_timeout = !timeout.is_null();
    let timeout_duration = if has_timeout {
        let ts = unsafe { timeout.as_ref().ok_or(LinuxError::EFAULT)? };
        if ts.tv_sec == 0 && ts.tv_nsec == 0 {
            // 立即返回的特殊情况
            return curr
                .task_ext()
                .process_data()
                .signal
                .lock()
                .take_pending_in(sigset)
                .ok_or(LinuxError::EAGAIN)
                .map(|sig| sig as isize);
        }
        Some(Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32))
    } else {
        None
    };

    // 主等待循环
    loop {
        // 检查是否有待处理的信号
        if let Some(sig) = curr
            .task_ext()
            .process_data()
            .signal
            .lock()
            .take_pending_in(sigset)
        {
            debug!("Received signal: {:?}", sig);
            return Ok(sig as isize);
        }

        // 检查超时
        if let Some(duration) = timeout_duration {
            let elapsed = monotonic_time() - start_time;
            if elapsed >= duration {
                return Err(LinuxError::EAGAIN);
            }
        }

        // 让出CPU
        yield_with_time_stat();
    }
}

pub(crate) fn sys_rt_sigsuspend(mask_ptr: *const sigset_t, sigsetsize: usize) -> LinuxResult<isize> {
    // 1. 验证信号集大小
    if sigsetsize != core::mem::size_of::<sigset_t>() {
        return Err(LinuxError::EINVAL);
    }
    // 2. 从用户空间读取信号掩码
    let new_mask: SignalSet = unsafe {
        let mask_ref = mask_ptr.as_ref().ok_or(LinuxError::EFAULT)?;
        (*mask_ref).into()
    };
    // 3. 获取当前进程和信号上下文
    let curr = current();
    let mut sigctx = curr.task_ext().process_data().signal.lock();
    // 4. 保存当前信号掩码
    // 假设 set_mask 返回旧的掩码（需确认实际实现）
    let old_mask = sigctx.set_mask(new_mask);
    // 5. 挂起进程，等待信号
    loop {
        // 检查是否有待处理的信号（未被屏蔽的信号）
        if sigctx.has_pending() {
            // 如果有待处理信号，恢复原来的信号掩码并返回
            sigctx.set_mask(old_mask);
            return Err(LinuxError::EINTR);
        }
        // 让出 CPU，进入等待状态
        drop(sigctx); // 释放锁，避免死锁
        yield_with_time_stat();
        sigctx = curr.task_ext().process_data().signal.lock(); // 重新获取锁
    }
}

pub(crate) fn handle_pending_signals(current_tf: &TrapFrame) {
    let curr = current();
    let mut sigctx = curr.task_ext().process_data().signal.lock();
    if !sigctx.has_pending() {
        return;
    }
    sigctx.set_current_stack(SignalStackType::Primary);
    // unlock sigctx since handle_pending_signals might exit curr context
    match axsignal::handle_pending_signals(&mut sigctx, current_tf, unsafe {
        trampoline_vaddr(sigreturn_trampoline as usize).into()
    }) {
        Ok(Some((mut uctx, kstack_top))) => {
            // 交换tf
            unsafe { write_trapframe_to_kstack(curr.get_kernel_stack_top().unwrap(), &uctx.0) };
        }
        Ok(None) => {}
        Err(_) => {}
    };
}

pub(crate) fn sys_sigreturn() -> LinuxResult<isize> {
    let curr = current();
    let mut sigctx = curr.task_ext().process_data().signal.lock();
    let (sscratch, mut tf) = sigctx.unload().unwrap();
    // 交换回tf, 返回a0以防止覆盖
    unsafe { write_trapframe_to_kstack(curr.get_kernel_stack_top().unwrap(), &tf) };
    unsafe { axhal::arch::exchange_trap_frame(sscratch) };
    debug!("sigreturn");
    Ok(tf.arg0() as isize)
}
