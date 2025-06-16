use alloc::{
    string::String,
    sync::{Arc, Weak},
    vec::Vec,
};
use signal::handle_pending_signals;
use spin::{Once, RwLock};
use weak_map::WeakMap;

use axerrno::{AxResult, LinuxError, LinuxResult};
use axfs::api::set_current_dir;
use axhal::{
    time::{NANOS_PER_MICROS, NANOS_PER_SEC, monotonic_time_nanos},
    trap::{POST_TRAP, PRE_TRAP, register_trap_handler},
};
use axprocess::{Pid, Process, ProcessGroup, Session, Thread};
use axsignal::{SignalContext, SignalSet, SignalStackType};
use core::{
    alloc::Layout,
    cell::RefCell,
    sync::atomic::{AtomicU64, AtomicUsize},
};
use memory_addr::{VirtAddr, VirtAddrRange};
use time::TimeStat;
use xmas_elf::symbol_table::Type::File;

use axhal::arch::{TrapFrame, UspaceContext};
use axmm::AddrSpace;
use axns::{AxNamespace, AxNamespaceIf};
use axsync::Mutex;
use axtask::{AxTaskRef, TaskExtRef, TaskInner, WaitQueue, current, yield_now};

#[cfg(feature = "sig")]
pub mod signal;
#[cfg(feature = "sig")]
pub use signal::*;

pub mod time;
pub use time::*;

pub mod process;
pub use process::*;

pub mod wait;
pub use wait::sys_waitpid;
pub mod exit;
pub use exit::sys_exit;

/// Task extended data for the monolithic kernel.
pub struct TaskExt {
    pub time: RefCell<time::TimeStat>,
    pub thread: Arc<Thread>,
}

#[allow(unused)]
impl TaskExt {
    pub fn new(thread: Arc<Thread>) -> Self {
        Self {
            /*
             *proc_id,
             *parent_id: AtomicU64::new(1),
             *children: Mutex::new(Vec::new()),
             *uctx,
             *clear_child_tid: AtomicU64::new(0),
             *aspace,
             *ns: AxNamespace::new_thread_local(false),
             *time: TimeStat::new().into(),
             */
            time: RefCell::new(TimeStat::new()),
            thread,
        }
    }

    /// Get the [`ThreadData`] associated with this task.
    pub fn thread_data(&self) -> &ThreadData {
        self.thread.data().unwrap()
    }

    /// Get the [`ProcessData`] associated with this task.
    pub fn process_data(&self) -> &ProcessData {
        self.thread.process().data().unwrap()
    }

    pub(crate) fn time_stat_from_kernel_to_user(&self, current_tick: usize) {
        self.time.borrow_mut().switch_into_user_mode(current_tick);
    }

    pub(crate) fn time_stat_from_user_to_kernel(&self, current_tick: usize) {
        self.time.borrow_mut().switch_into_kernel_mode(current_tick);
    }

    pub(crate) fn time_stat_output(&self) -> (usize, usize) {
        self.time.borrow().output()
    }

    pub(crate) fn set_heap_top(&self, top: VirtAddr) -> VirtAddr {
        self.process_data().aspace.lock().set_heap_top(top)
    }

    pub(crate) fn set_heap_size(&self, size: usize) -> VirtAddr {
        self.process_data().aspace.lock().set_heap_size(size)
    }

    pub(crate) fn heap_size(&self) -> usize {
        self.process_data().aspace.lock().heap().size()
    }

    pub(crate) fn heap_top(&self) -> VirtAddr {
        self.process_data().aspace.lock().heap().top()
    }
}

struct AxNamespaceImpl;
#[crate_interface::impl_interface]
impl AxNamespaceIf for AxNamespaceImpl {
    fn current_namespace_base() -> *mut u8 {
        // Namespace for kernel task
        static KERNEL_NS_BASE: Once<usize> = Once::new();
        let current = axtask::current();
        // Safety: We only check whether the task extended data is null and do not access it.
        if unsafe { current.task_ext_ptr() }.is_null() {
            return *(KERNEL_NS_BASE.call_once(|| {
                let global_ns = AxNamespace::global();
                let layout = Layout::from_size_align(global_ns.size(), 64).unwrap();
                // Safety: The global namespace is a static readonly variable and will not be dropped.
                let dst = unsafe { alloc::alloc::alloc(layout) };
                let src = global_ns.base();
                unsafe { core::ptr::copy_nonoverlapping(src, dst, global_ns.size()) };
                dst as usize
            })) as *mut u8;
        }
        current.task_ext().process_data().ns.base()
    }
}

axtask::def_task_ext!(TaskExt);

pub fn spawn_user_task_inner(exe_path: &str, uctx: UspaceContext, pwd: String) -> TaskInner {
    let mut task = TaskInner::new(
        move || {
            let curr = axtask::current();
            let kstack_top = curr.kernel_stack_top().unwrap();
            trace!(
                "Enter user space: entry={:#x}, ustack={:#x}, kstack={:#x}",
                uctx.get_ip(),
                uctx.get_sp(),
                kstack_top,
            );
            // FIXME:
            set_current_dir(pwd.as_str()).unwrap();
            unsafe { uctx.enter_uspace(kstack_top) };
        },
        exe_path.into(),
        axconfig::plat::KERNEL_STACK_SIZE,
    );

    task
}

pub fn spawn_user_task(
    exe_path: &str,
    aspace: Arc<Mutex<AddrSpace>>,
    uctx: UspaceContext,
    pwd: String,
    parent: Option<Arc<Process>>,
) -> AxTaskRef {
    let mut task = spawn_user_task_inner(exe_path, uctx, pwd);
    task.ctx_mut()
        .set_page_table_root(aspace.lock().page_table_root());
    let tid = task.id().as_u64() as Pid;

    //let aspace_ = aspace.lock();
    //aspace_.map_alloc(size, flags, populate);
    //let sigctx = SignalContext::default();
    //sigctx.set_stack(SignalStackType::Primary, range);

    /*
     *let process_data = ProcessData {
     *    exe_path: RwLock::new(exe_path.into()),
     *    aspace,
     *    ns: AxNamespace::new_thread_local(),
     *    child_exit_wq: WaitQueue::new(),
     *    exit_signal: None,
     *    signal: Arc::new(Mutex::new(SignalContext::default())),
     *};
     */
    let process_data = ProcessData::new(exe_path.into(), aspace, spawn_signal_ctx(), None);
    let parent = parent.unwrap_or(init_proc());
    let process = parent.fork(tid).data(process_data).build();

    let thread_data = ThreadData {
        clear_child_tid: AtomicUsize::new(0),
    };
    let thread = process.new_thread(tid).data(thread_data).build();

    task.init_task_ext(TaskExt::new(thread));

    task.task_ext().process_data().ns_init_new();
    task.into_arc()
}

pub fn init_proc() -> Arc<Process>{
    axprocess::init_proc()
}

pub unsafe fn write_trapframe_to_kstack(kstack_top: usize, trap_frame: &TrapFrame) {
    let trap_frame_size = core::mem::size_of::<TrapFrame>();
    let trap_frame_ptr = (kstack_top - trap_frame_size) as *mut TrapFrame;
    unsafe {
        *trap_frame_ptr = *trap_frame;
    }
}

pub fn read_trapframe_from_kstack(kstack_top: usize) -> TrapFrame {
    let trap_frame_size = core::mem::size_of::<TrapFrame>();
    let trap_frame_ptr = (kstack_top - trap_frame_size) as *mut TrapFrame;
    unsafe { *trap_frame_ptr }
}

static THREAD_TABLE: RwLock<WeakMap<Pid, Weak<Thread>>> = RwLock::new(WeakMap::new());
static PROCESS_TABLE: RwLock<WeakMap<Pid, Weak<Process>>> = RwLock::new(WeakMap::new());
static PROCESS_GROUP_TABLE: RwLock<WeakMap<Pid, Weak<ProcessGroup>>> = RwLock::new(WeakMap::new());
static SESSION_TABLE: RwLock<WeakMap<Pid, Weak<Session>>> = RwLock::new(WeakMap::new());

/// Add the thread and possibly its process, process group and session to the
/// corresponding tables.
pub fn add_thread_to_table(thread: &Arc<Thread>) {
    let mut thread_table = THREAD_TABLE.write();
    thread_table.insert(thread.tid(), thread);

    let mut process_table = PROCESS_TABLE.write();
    let process = thread.process();
    if process_table.contains_key(&process.pid()) {
        return;
    }
    process_table.insert(process.pid(), process);

    let mut process_group_table = PROCESS_GROUP_TABLE.write();
    let process_group = process.group();
    if process_group_table.contains_key(&process_group.pgid()) {
        return;
    }
    process_group_table.insert(process_group.pgid(), &process_group);

    let mut session_table = SESSION_TABLE.write();
    let session = process_group.session();
    if session_table.contains_key(&session.sid()) {
        return;
    }
    session_table.insert(session.sid(), &session);
}

/// Lists all processes.
pub fn processes() -> Vec<Arc<Process>> {
    PROCESS_TABLE.read().values().collect()
}

/// Finds the thread with the given TID.
pub fn get_thread(tid: Pid) -> LinuxResult<Arc<Thread>> {
    THREAD_TABLE.read().get(&tid).ok_or(LinuxError::ESRCH)
}
/// Finds the process with the given PID.
pub fn get_process(pid: Pid) -> LinuxResult<Arc<Process>> {
    PROCESS_TABLE.read().get(&pid).ok_or(LinuxError::ESRCH)
}
/// Finds the process group with the given PGID.
pub fn get_process_group(pgid: Pid) -> LinuxResult<Arc<ProcessGroup>> {
    PROCESS_GROUP_TABLE
        .read()
        .get(&pgid)
        .ok_or(LinuxError::ESRCH)
}
/// Finds the session with the given SID.
pub fn get_session(sid: Pid) -> LinuxResult<Arc<Session>> {
    SESSION_TABLE.read().get(&sid).ok_or(LinuxError::ESRCH)
}

/// Update the time statistics to reflect a switch from kernel mode to user mode.
pub fn time_stat_from_kernel_to_user() {
    let curr_task = current();
    curr_task
        .task_ext()
        .time_stat_from_kernel_to_user(monotonic_time_nanos() as usize);
}

/// Update the time statistics to reflect a switch from user mode to kernel mode.
pub fn time_stat_from_user_to_kernel() {
    let curr_task = current();
    curr_task
        .task_ext()
        .time_stat_from_user_to_kernel(monotonic_time_nanos() as usize);
}

pub fn time_stat_to_new_task() {
    let curr_task = current();
    curr_task
        .task_ext()
        .time
        .borrow_mut()
        .switch_to_new_task(monotonic_time_nanos() as usize);
}

pub fn time_stat_from_old_task() {
    let curr_task = current();
    curr_task
        .task_ext()
        .time
        .borrow_mut()
        .switch_from_old_task(monotonic_time_nanos() as usize);
}

/// Get the time statistics for the current task.
pub fn time_stat_output() -> (usize, usize, usize, usize) {
    let curr_task = current();
    let (utime_ns, stime_ns) = curr_task.task_ext().time_stat_output();
    (
        utime_ns / NANOS_PER_SEC as usize,
        utime_ns / NANOS_PER_MICROS as usize,
        stime_ns / NANOS_PER_SEC as usize,
        stime_ns / NANOS_PER_MICROS as usize,
    )
}
/// Better using this instead of [`axtask::api::yield_now`]
/// to get time statistics
pub fn yield_with_time_stat() {
    time_stat_to_new_task();
    yield_now();
    time_stat_from_old_task();
}

#[register_trap_handler(PRE_TRAP)]
fn pre_trap_handler(trap_frame: &mut TrapFrame, from_user: bool) -> bool {
    if from_user {
        time_stat_from_user_to_kernel();
        handle_pending_signals(trap_frame);
    }
    true
}

#[register_trap_handler(POST_TRAP)]
fn post_trap_handler(trap_frame: &mut TrapFrame, from_user: bool) -> bool {
    if from_user {
        time_stat_from_kernel_to_user();
        handle_pending_signals(trap_frame);
    }
    true
}
