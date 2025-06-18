use axprocess::Pid;
use axsignal::{Signal, SignalSet};
//use axsignal::{SignalInfo, Signo};
use crate::task::ProcessData;
use axtask::{TaskExtRef, current};
use linux_raw_sys::general::SI_KERNEL;

use crate::ptr::{PtrWrapper, UserPtr};

pub fn do_exit(exit_code: i32, group_exit: bool) -> ! {
    let curr = current();
    let curr_ext = curr.task_ext();

    let thread = &curr_ext.thread;
    info!("{:?} exit with code: {}", thread, exit_code);

    let clear_child_tid = UserPtr::<i32>::from(curr_ext.thread_data().clear_child_tid());
    if let Ok(clear_tid_ptr) = clear_child_tid.get() {
        unsafe {
            // 将 clear_child_tid 地址清零
            clear_tid_ptr.write(0);
            // 唤醒等待在该地址上的 futex
            axtask::futex_wake(clear_tid_ptr, 1); // 唤醒一个等待者
        }
    }

    let process = thread.process();
    if thread.exit(exit_code) {
        process.exit();
        if let Some(parent) = process.parent() {
            if let Some(data) = parent.data::<ProcessData>() {
                debug!("send SIGCHLD to parent {:?}", parent.pid());
                data.signal.lock().send_signal(SignalSet::SIGCHLD);
                data.child_exit_wq.notify_all(false);
            }
        }

        process.exit();
        // TODO: clear namespace resources
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
