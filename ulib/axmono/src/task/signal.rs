use core::{ffi::c_int, time::Duration};

use alloc::sync::Arc;
//use arceos_posix_api::ctypes::{self, *};
use axerrno::{LinuxError, LinuxResult, ax_err};
use axhal::{arch::TrapFrame, time::monotonic_time};
use axprocess::{Pid, Process, ProcessGroup, Thread};
use axsignal::{siginfo::SigInfo, *};
use axsync::Mutex;
use axtask::{TaskExtRef, current, exit, yield_now};
use linux_raw_sys::general::*;
use memory_addr::{VirtAddr, VirtAddrRange};

use crate::{
    mm::trampoline_vaddr,
    ptr::{PtrWrapper, UserPtr},
    task::{PROCESS_GROUP_TABLE, sys_exit},
};

use super::{
    PROCESS_TABLE, ProcessData, THREAD_TABLE, ThreadData, find_thread_in_group, get_process,
    get_process_group, get_thread, processes, time::TimeStat, time_stat_from_old_task,
    time_stat_to_new_task, write_trapframe_to_kstack, yield_with_time_stat,
};

pub fn default_signal_handler(signal: Signal, ctx: &mut SignalContext) {
    match signal {
        Signal::SIGINT | Signal::SIGKILL => {
            // 杀死进程
            let curr = current();
            debug!("kill myself");
            sys_exit(curr.task_ext().thread.process().exit_code());
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

/*
 *pub(crate) fn sys_kill(pid: c_int, sig: c_int) -> LinuxResult<isize> {
 *    let sig = Signal::from_u32(sig as _).ok_or(LinuxError::EINVAL)?;
 *    if pid > 0 {
 *        let process = PROCESS_TABLE
 *            .read()
 *            .get(&(pid as _))
 *            .ok_or(LinuxError::ESRCH)?;
 *        let data: &ProcessData = process.data().ok_or_else(|| {
 *            error!("Process {} has no data", pid);
 *            LinuxError::EFAULT
 *        })?;
 *        data.send_signal(sig);
 *    } else {
 *        warn!("Not supported yet: pid: {:?}", pid);
 *        return Err(LinuxError::EINVAL);
 *    }
 *    Ok(0)
 *}
 */

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
                .consume_one_in(sigset)
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
            .consume_one_in(sigset)
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

pub(crate) fn sys_rt_sigsuspend(
    mask_ptr: *const sigset_t,
    sigsetsize: usize,
) -> LinuxResult<isize> {
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

/*
 *pub(crate) fn handle_pending_signals(current_tf: &TrapFrame) {
 *    let curr = current();
 *    let mut sigctx = curr.task_ext().process_data().signal.lock();
 *    if !sigctx.has_pending() {
 *        return;
 *    }
 *    sigctx.set_current_stack(SignalStackType::Primary);
 *    // unlock sigctx since handle_pending_signals might exit curr context
 *    match axsignal::handle_pending_signals(&mut sigctx, current_tf, unsafe {
 *        trampoline_vaddr(sigreturn_trampoline as usize).into()
 *    }) {
 *        Ok(Some((mut uctx, kstack_top))) => {
 *            // 交换tf
 *            unsafe { write_trapframe_to_kstack(curr.get_kernel_stack_top().unwrap(), &uctx.0) };
 *        }
 *        Ok(None) => {}
 *        Err(_) => {}
 *    };
 *}
 */

pub(crate) fn handle_pending_signals(current_tf: &TrapFrame) {
    let curr = current();

    // 首先检查进程级别的信号处理
    let mut proc_sigctx = curr.task_ext().process_data().signal.lock();
    if proc_sigctx.has_pending() {
        warn!("a");
        proc_sigctx.set_current_stack(SignalStackType::Primary);
        match axsignal::handle_pending_signals(
            &mut proc_sigctx,
            current_tf,
            unsafe { trampoline_vaddr(sigreturn_trampoline as usize).into() },
            None,
        ) {
            Ok(Some((mut uctx, _kstack_top))) => {
                // 交换tf
                unsafe { write_trapframe_to_kstack(curr.get_kernel_stack_top().unwrap(), &uctx.0) };
                return;
            }
            Ok(None) => {}
            Err(_) => {}
        }
    }

    // 然后检查线程级别的信号处理
    let mut thread_sigctx = curr.task_ext().thread_data().signal().lock();
    if thread_sigctx.has_pending() {
        thread_sigctx.set_current_stack(SignalStackType::Primary);
        match axsignal::handle_pending_signals(
            &mut thread_sigctx,
            current_tf,
            unsafe { trampoline_vaddr(sigreturn_trampoline as usize).into() },
            Some(&mut proc_sigctx),
        )
        .inspect_err(|e| warn!("{e:?}"))
        {
            Ok(Some((mut uctx, _kstack_top))) => {
                warn!("123");
                // 交换tf
                unsafe { write_trapframe_to_kstack(curr.get_kernel_stack_top().unwrap(), &uctx.0) };
                return;
            }
            Ok(None) => {}
            Err(_) => {}
        }
    }
}

pub(crate) fn sys_sigreturn() -> LinuxResult<isize> {
    let curr = current();
    trace!("sigreturn");
    let (sscratch, mut tf) = {
        let mut sigctx = curr.task_ext().process_data().signal.lock();
        let mut t_sigctx = curr.task_ext().thread_data().signal.lock();
        t_sigctx.unload().or(sigctx.unload()).expect("No sig frame loaded")
    };
    // 交换回tf, 返回a0
    unsafe { write_trapframe_to_kstack(curr.get_kernel_stack_top().unwrap(), &tf) };
    unsafe { axhal::arch::exchange_trap_frame(sscratch) };
    Ok(tf.arg0() as isize)
}

#[derive(Clone, Copy)]
pub(crate) enum SigInfo_ {
    Generic(SigCodeCommon),                     // pid, uid
    Child(SigCodeSigChld, SigStatus, u64, u64), // pid, uid, status, utime, stime
    MemoryAccess(VirtAddr),                     // addr
    FPEError(VirtAddr),                         // addr
    IllegalInstruction(VirtAddr),               // addr
    BusError(VirtAddr),                         // addr
    Realtime(i32, VirtAddr),                    // value, ptr
    PollIO(i32, i64),                           // fd, band
    SyscallError(usize, i32, u32),              // call_addr, syscall_num, arch
    Simple(SigCode),
}

fn gen_siginfo(signo: Signal, data: SigInfo_) -> SigInfo {
    let curr = current();
    let current_pid = curr.task_ext().thread.process().pid() as i32;
    let current_uid = 0; // 假设 uid 为 0，实际应从进程或用户管理中获取
    match data {
        SigInfo_::Generic(code) => SigInfo::new_generic(signo, code, current_pid, current_uid),
        SigInfo_::Child(code, status, utime, stime) => {
            SigInfo::new_child(signo, code, current_pid, current_uid, status, utime, stime)
        }
        //SigInfo_::MemoryAccess(addr) => SigInfo::new_memory_access(signo, code, addr),
        //SigInfo_::FPEError(addr) => SigInfo::new_fpe_error(signo, code, addr),
        //SigInfo_::IllegalInstruction(addr) => SigInfo::new_illegal_instruction(signo, code, addr),
        //SigInfo_::BusError(addr) => SigInfo::new_bus_error(signo, code, addr),
        //SigInfo_::Realtime(value, ptr) => SigInfo::new_realtime(signo, code, value, ptr),
        //SigInfo_::PollIO(fd, band) => SigInfo::new_poll_io(signo, code, fd, band),
        /*
         *SigInfo_::SyscallError(call_addr, syscall_num, arch) => {
         *    SigInfo::new_syscall_error(signo, code, call_addr, syscall_num, arch)
         *}
         */
        SigInfo_::Simple(code) => SigInfo::new_simple(signo, code),
        _ => todo!(),
    }
}

/// Send a signal to a thread.
/// helper function from starryx
pub fn send_signal_thread(thr: &Thread, sig: Signal, info: SigInfo_) -> LinuxResult<()> {
    info!("Send signal {:?} to thread {}", sig, thr.tid());
    let Some(thr) = thr.data::<ThreadData>() else {
        return Err(LinuxError::EPERM);
    };
    thr.send_signal(sig, Some(gen_siginfo(sig, info)));
    Ok(())
}

/// Send a signal to a process.
/// helper function from starryx
pub fn send_signal_process(proc: &Process, sig: Signal, info: SigInfo_) -> LinuxResult<()> {
    info!("Send signal {:?} to process {}", sig, proc.pid());
    let Some(proc) = proc.data::<ProcessData>() else {
        return Err(LinuxError::EPERM);
    };
    proc.send_signal(sig, Some(gen_siginfo(sig, info)));
    Ok(())
}

/// Send a signal to a process group.
/// helper function from starryx
pub fn send_signal_process_group(pg: &ProcessGroup, sig: Signal, info: SigInfo_) -> usize {
    info!("Send signal {:?} to process group {}", sig, pg.pgid());
    let mut count = 0;
    for proc in pg.processes() {
        count += send_signal_process(&proc, sig.clone(), info).is_ok() as usize;
    }
    count
}
pub fn sys_kill(pid: c_int, signo: u32) -> LinuxResult<isize> {
    let Some(sig) = Signal::from_u32(signo) else {
        return Ok(0); // 信号无效
    };
    let info = SigInfo_::Generic(SigCodeCommon::SI_USER);
    match pid {
        1.. => {
            // pid > 0: 发送信号给指定进程
            let proc = get_process(pid as Pid)?;
            send_signal_process(&proc, sig, info)?;
            Ok(0) // 成功发送信号通常返回0
        }
        0 => {
            // pid = 0: 发送信号给当前进程组中的所有进程
            let pg = current().task_ext().thread.process().group();
            send_signal_process_group(&pg, sig, info);
            Ok(0)
        }
        -1 => {
            // pid = -1: 发送信号给所有进程（除了init进程）
            let mut count = 0;
            for proc in processes() {
                if proc.is_init() {
                    continue;
                }
                send_signal_process(&proc, sig.clone(), info)?;
                count += 1;
            }
            Ok(count as isize)
        }
        ..-1 => {
            // pid < -1: 发送信号给指定进程组
            let pg = get_process_group((-pid) as Pid)?;
            Ok(send_signal_process_group(&pg, sig, info) as isize)
        }
    }
}
pub fn sys_tkill(tid: Pid, signo: u32) -> LinuxResult<isize> {
    let Some(sig) = Signal::from_u32(signo) else {
        warn!("{signo:?}");
        return Ok(0); // 信号无效
    };
    let info = SigInfo_::Generic(SigCodeCommon::SI_USER);
    warn!("{sig:?}");
    let thr = get_thread(tid)?;
    send_signal_thread(&thr, sig, info)?;
    Ok(0)
}
pub fn sys_tgkill(tgid: Pid, tid: Pid, signo: u32) -> LinuxResult<isize> {
    let Some(sig) = Signal::from_u32(signo) else {
        return Ok(0); // 信号无效
    };
    let info = SigInfo_::Generic(SigCodeCommon::SI_USER);
    send_signal_thread(find_thread_in_group(tgid, tid)?.as_ref(), sig, info)?;
    Ok(0)
}
