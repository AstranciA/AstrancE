//! **代码来源声明：**
//! 本文件代码来自
//! [oscomp/starry-next](https://github.com/oscomp/starry-next) 项目。
//!
use crate::{
    ptr::{PtrWrapper, UserPtr},
    task::ProcessData,
};
use alloc::{sync::Arc, vec::Vec};
use axerrno::{LinuxError, LinuxResult};
use axprocess::{Pid, Process};
use axtask::{TaskExtRef, current};
use bitflags::bitflags;
use linux_raw_sys::general::{
    __WALL, __WCLONE, __WNOTHREAD, WCONTINUED, WEXITED, WNOHANG, WNOWAIT, WUNTRACED,
};

bitflags! {
    #[derive(Debug)]
    struct WaitOptions: u32 {
        /// Do not block when there are no processes wishing to report status.
        const WNOHANG = WNOHANG;
        /// Report the status of selected processes which are stopped due to a
        /// `SIGTTIN`, `SIGTTOU`, `SIGTSTP`, or `SIGSTOP` signal.
        const WUNTRACED = WUNTRACED;
        /// Report the status of selected processes which have terminated.
        const WEXITED = WEXITED;
        /// Report the status of selected processes that have continued from a
        /// job control stop by receiving a `SIGCONT` signal.
        const WCONTINUED = WCONTINUED;
        /// Don't reap, just poll status.
        const WNOWAIT = WNOWAIT;

        /// Don't wait on children of other threads in this group
        const WNOTHREAD = __WNOTHREAD;
        /// Wait on all children, regardless of type
        const WALL = __WALL;
        /// Wait for "clone" children only.
        const WCLONE = __WCLONE;
    }
}

#[derive(Debug, Clone, Copy)]
enum WaitPid {
    /// Wait for any child process
    Any,
    /// Wait for the child whose process ID is equal to the value.
    Pid(Pid),
    /// Wait for any child process whose process group ID is equal to the value.
    Pgid(Pid),
}

impl WaitPid {
    fn apply(&self, child: &Arc<Process>) -> bool {
        match self {
            WaitPid::Any => true,
            WaitPid::Pid(pid) => child.pid() == *pid,
            WaitPid::Pgid(pgid) => child.group().pgid() == *pgid,
        }
    }
}

pub fn sys_waitpid(pid: i32, exit_code_ptr: UserPtr<i32>, options: u32) -> LinuxResult<isize> {
    // TODO: support all flags
    let options = WaitOptions::from_bits_truncate(options);
    info!("sys_waitpid <= pid: {:?}, options: {:?}", pid, options);

    let curr = current();
    let proc_data = curr.task_ext().process_data();
    let process = curr.task_ext().thread.process();

    let pid = if pid == -1 {
        WaitPid::Any
    } else if pid == 0 {
        WaitPid::Pgid(process.group().pgid())
    } else if pid > 0 {
        WaitPid::Pid(pid as _)
    } else {
        WaitPid::Pgid(-pid as _)
    };
    let pch = process.children();
    let children = pch
        .into_iter()
        .filter(|child| pid.apply(child))
        .filter(|child| {
            options.contains(WaitOptions::WALL)
                || (options.contains(WaitOptions::WCLONE)
                    == child.data::<ProcessData>().unwrap().is_clone_child())
        })
        .collect::<Vec<_>>();
    if children.is_empty() {
        return Err(LinuxError::ECHILD);
        // return  Ok(0);
    }
    

    let exit_code = exit_code_ptr.nullable(UserPtr::get)?;
    loop {
        if let Some(child) = children.iter().find(|child| child.is_zombie()) {
            debug!("found zombie child: {:?}", child);
            if !options.contains(WaitOptions::WNOWAIT) {
                child.free();
            }
            if let Some(exit_code) = exit_code {
                unsafe { exit_code.write(child.exit_code()) };
            }
            return Ok(child.pid() as _);
        } else if options.contains(WaitOptions::WNOHANG) {
            return Ok(0);
        } else {
            debug!("keep waiting for children");
            proc_data.child_exit_wq.wait();
        }
    }
}
