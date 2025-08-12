//! **代码来源声明：**
//! 本文件代码参考
//! [oscomp/starry-next](https://github.com/oscomp/starry-next) 项目。
//!
use arceos_posix_api::FD_TABLE;
use axprocess::Pid;
use axsignal::{SigCode, SigCodeSigChld, SigStatus, Signal, SignalSet};
//use axsignal::{SignalInfo, Signo};
use crate::task::{process, send_signal_process, ProcessData, SigInfo_};
use axtask::{TaskExtRef, current};
use linux_raw_sys::general::SI_KERNEL;
use crate::ptr::{PtrWrapper, UserPtr};


pub fn do_exit(exit_code: i32, group_exit: bool) -> ! {
    let curr = current();
    let curr_ext = curr.task_ext();

    let thread = &curr_ext.thread;
    info!("{:?} exit with code: {}", thread, exit_code);

    // process::exit_robust_list(&curr_ext.thread_data());
    let clear_child_tid = UserPtr::<Pid>::from(curr_ext.thread_data().clear_child_tid());
    if let Ok(clear_tid) = clear_child_tid.get() {
        unsafe { clear_tid.write(0) };
        // TODO: wake up threads, which are blocked by futex, and waiting for the address pointed by clear_child_tid
    }

    let process = thread.process();
    if thread.exit(exit_code) || true {
        if let Some(parent) = process.parent() {
            /*
             *if let Some(signo) = process.data::<ProcessData>().and_then(|it| it.exit_signal) {
             *    let _ = send_signal_process(&parent, SignalInfo::new(signo, SI_KERNEL as _));
             *}
             */
            if let Some(parent_data) = parent.data::<ProcessData>() {
                let sig = process
                    .data::<ProcessData>()
                    .and_then(|it| it.exit_signal)
                    .unwrap_or(Signal::SIGCHLD);
                debug!("send {:?} to parent {:?}", sig, parent.pid());
                send_signal_process(
                    &parent.clone(),
                    sig,
                    SigInfo_::Child(
                        SigCodeSigChld::CLD_EXITED,
                        SigStatus::ExitCode(exit_code),
                        0,
                        0,
                    ),
                );
                parent_data.child_exit_wq.notify_all(false);
            }
        }

        process.exit();
        // TODO: clear namespace resources
        FD_TABLE.clear();
    }
    if group_exit && !process.is_group_exited() {
        process.group_exit();
        //let sig = SignalInfo::new(Signo::SIGKILL, SI_KERNEL as _);
        for thr in process.threads() {
            //let _ = send_signal_thread(&thr, sig.clone());
            // TODO: thread local sigctx
            //thr.data::<ThreadData>().and_then(||)
        }
    }
    axtask::exit(exit_code)
}

pub fn sys_exit(exit_code: i32) -> ! {
    do_exit(exit_code << 8, false)
}

pub fn sys_exit_group(exit_code: i32) -> ! {
    do_exit(exit_code << 8, true)
}
