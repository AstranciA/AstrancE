//! 提供了进程/线程管理以及上下文切换的相关实现。
//!
//! **代码来源声明：**
//! `clone` 系统调用相关的 `flag` 处理逻辑，参考并改编自
//! [oscomp/starry-next](https://github.com/oscomp/starry-next) 项目。
//!
use core::{
    ptr,
    sync::atomic::{AtomicUsize, Ordering},
};

use crate::{
    ctypes::TimeStat,
    elf::OwnedElfFile,
    mm::{load_elf_to_mem, map_trampoline},
    task::{add_thread_to_table, spawn_signal_ctx},
};
use alloc::{
    boxed::Box,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use arceos_posix_api::{FD_TABLE, ctypes::*};
use axerrno::{AxError, AxResult, LinuxError, LinuxResult};
use axfs::{
    CURRENT_DIR, CURRENT_DIR_PATH,
    api::{current_dir, set_current_dir},
};
use axhal::arch::UspaceContext;
use axio::Read;
use axmm::{AddrSpace, kernel_aspace};
use axns::AxNamespace;
use axprocess::Pid;
use axsignal::{siginfo::SigInfo, Signal, SignalContext};
use axsync::Mutex;
use axtask::{AxTaskRef, TaskExtRef, WaitQueue, current};
use core::ffi::c_int;
use memory_addr::VirtAddrRange;
use spin::RwLock;
use xmas_elf::program;

use crate::{
    copy_from_kernel,
    ctypes::{CloneFlags, WaitStatus},
    elf::ELFInfo,
    loader::load_elf_from_disk,
    mm::map_elf_sections,
    task::TaskExt,
    utils::get_pwd_from_envs,
};

use super::{read_trapframe_from_kstack, spawn_user_task, spawn_user_task_inner};

/// Extended data for [`Process`].
pub struct ProcessData {
    /// The executable path
    pub exe_path: RwLock<String>,
    /// The virtual memory address space.
    pub aspace: Arc<Mutex<AddrSpace>>,
    /// The resource namespace
    pub ns: AxNamespace,

    /// The child exit wait queue
    pub child_exit_wq: WaitQueue,
    /// The exit signal of the thread
    pub exit_signal: Option<Signal>,

    /// The process signal manager
    pub signal: Arc<Mutex<SignalContext>>,
    pub signal_stack: Box<[u8; 4096]>,
}
impl ProcessData {
    /// Create a new [`ProcessData`].
    pub fn new(
        exe_path: String,
        aspace: Arc<Mutex<AddrSpace>>,
        signal: Arc<Mutex<SignalContext>>,
        exit_signal: Option<Signal>,
    ) -> Self {
        let signal_stack = Box::new([0u8; 4096]);
        let signal__ = signal.clone();
        let mut signal_ = signal__.lock();

        signal_.set_current_stack(axsignal::SignalStackType::Primary);
        signal_.set_stack(
            axsignal::SignalStackType::Primary,
            VirtAddrRange::from_start_size((signal_stack.as_ptr() as usize).into(), 4096),
        );
        Self {
            exe_path: RwLock::new(exe_path),
            aspace,
            ns: AxNamespace::new_thread_local(),
            child_exit_wq: WaitQueue::new(),
            exit_signal,
            signal,
            signal_stack,
        }
    }
    /// Initialize the namespace for the new task.
    pub(crate) fn ns_init_new(&self) {
        let ns = &self.ns;
        FD_TABLE.deref_from(ns).init_new(FD_TABLE.copy_inner());
        CURRENT_DIR
            .deref_from(ns)
            .init_new(CURRENT_DIR.copy_inner());
        CURRENT_DIR_PATH
            .deref_from(ns)
            .init_new(CURRENT_DIR_PATH.copy_inner());
    }
    /// Linux manual: A "clone" child is one which delivers no signal, or a
    /// signal other than SIGCHLD to its parent upon termination.
    pub fn is_clone_child(&self) -> bool {
        self.exit_signal != Signal::from_u32(SIGCHLD)
    }

    pub fn signal(&self) -> &Arc<Mutex<SignalContext>> {
        &self.signal
    }

    pub fn send_signal(&self, sig: Signal, info: Option<SigInfo>) {
        self.signal.lock().send_signal(sig.into(), info);
    }
}
impl Drop for ProcessData {
    fn drop(&mut self) {
        if !cfg!(target_arch = "aarch64") && !cfg!(target_arch = "loongarch64") {
            // See [`crate::new_user_aspace`]

            debug!("Drop ProcessData");

            let kernel = kernel_aspace().lock();

            self.aspace
                .lock()
                .clear_mappings(VirtAddrRange::from_start_size(kernel.base(), kernel.size()));
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct RobustList {
    next: usize,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct RobustListHead {
    list: RobustList,
    futex_offset: isize,
    pending: *mut RobustList,
}

/// Extended data for [`Thread`].
pub struct ThreadData {
    /// The clear thread tid field
    ///
    /// See <https://manpages.debian.org/unstable/manpages-dev/set_tid_address.2.en.html#clear_child_tid>
    ///
    /// When the thread exits, the kernel clears the word at this address if it is not NULL.
    pub clear_child_tid: AtomicUsize,
    // The thread-level signal manager
    //pub signal: ThreadSignalManager<RawMutex, WaitQueueWrapper>,
    pub signal: Arc<Mutex<SignalContext>>,
/*
    /// user-space pointer to struct robust_list_head (0 == NULL)
    pub robust_list_head_ptr: AtomicUsize,
    /// size passed by user (0 if not set)
    pub robust_list_size: AtomicUsize,
*/
}

impl ThreadData {
    /// Create a new [`ThreadData`].
    #[allow(clippy::new_without_default)]
    pub fn new(proc: &ProcessData) -> Self {
        let signal_stack = Box::new([0u8; 4096]);
        let signalctx = spawn_signal_ctx();
        let mut signal_ = signalctx.lock();

        signal_.set_current_stack(axsignal::SignalStackType::Primary);
        signal_.set_stack(
            axsignal::SignalStackType::Primary,
            VirtAddrRange::from_start_size((signal_stack.as_ptr() as usize).into(), 4096),
        );
        drop(signal_);
        Self {
            clear_child_tid: AtomicUsize::new(0),
            signal: signalctx, // FIXME: thread sig ctx
            // robust_list_head_ptr: AtomicUsize::new(0),
            // robust_list_size: AtomicUsize::new(0),
        }
    }

    /// Get the clear child tid field.
    pub fn clear_child_tid(&self) -> usize {
        self.clear_child_tid.load(Ordering::Relaxed)
    }

    /// Set the clear child tid field.
    pub fn set_clear_child_tid(&self, clear_child_tid: usize) {
        self.clear_child_tid
            .store(clear_child_tid, Ordering::Relaxed);
    }

    pub fn signal(&self) -> &Arc<Mutex<SignalContext>> {
        &self.signal
    }

    pub fn send_signal(&self, sig: Signal, info: Option<SigInfo>) {
        self.signal.lock().send_signal(sig.into(), info);
    }

    // pub fn set_robust_list(&self, head_ptr: usize, size: usize) {
    //     self.robust_list_head_ptr.store(head_ptr, Ordering::SeqCst);
    //     self.robust_list_size.store(size, Ordering::SeqCst);
    // }
    // pub fn get_robust_list(&self) -> (usize, usize) {
    //     (
    //         self.robust_list_head_ptr.load(Ordering::SeqCst),
    //         self.robust_list_size.load(Ordering::SeqCst),
    //     )
    // }
}

///TODO: finish the exit of robust list
/*pub fn exit_robust_list(td: &ThreadData) {
    let (head_addr, size) = td.robust_list();
    if head_addr == 0 || size != core::mem::size_of::<RobustListHead>() {
        return;
    }

    // 从用户空间拷贝 robust_list_head
    let mut head: RobustListHead = RobustListHead {
        list: RobustList { next: 0 },
        futex_offset: 0,
        pending: 0,
    };
    if copy_from_user(&mut head, head_addr as *const _, size).is_err() {
        return;
    }

    let mut futexes: Vec<usize> = Vec::new();

    // 先处理 pending 节点
    if head.pending != 0 {
        let futex_addr = (head.pending as isize + head.futex_offset) as usize;
        futexes.push(futex_addr);
    }

    // 遍历链表
    let mut node_ptr = head.list.next;
    let mut loop_count = 0;
    while node_ptr != head_addr && node_ptr != 0 {
        // 防止用户态构造死循环
        if loop_count > 4096 { break; }
        loop_count += 1;

        // 读取下一个节点地址
        let mut node: RobustList = RobustList { next: 0 };
        if copy_from_user(&mut node, node_ptr as *const _, core::mem::size_of::<RobustList>()).is_err() {
            break;
        }

        // 计算 futex 地址
        let futex_addr = (node_ptr as isize + head.futex_offset) as usize;
        futexes.push(futex_addr);

        node_ptr = node.next;
    }

    // 对所有 futex 执行 OWNER_DIED + 唤醒
    for addr in futexes {
        let mut val: u32 = 0;
        if copy_from_user(&mut val, addr as *const _, 4).is_ok() {
            // 标记 OWNER_DIED，清 tid
            let new_val = (val & !0x3fffffff) | 0x40000000; // FUTEX_OWNER_DIED
            let _ = copy_to_user(addr as *mut _, &new_val, 4);
            futex_wake(addr, 1); // 唤醒一个等待者
        }
    }
}*/

/// fork current task
/// **Return**
/// - `Ok(new_task_ref)` if fork successfully
pub fn fork(from_umode: bool) -> LinuxResult<AxTaskRef> {
    clone_task(None, CloneFlags::empty(), from_umode, 0, 0, 0)
}

pub fn clone_task(
    stack: Option<usize>,
    flags: CloneFlags,
    from_umode: bool,
    parent_tid: usize,
    child_tid: usize,
    tls: usize,
) -> LinuxResult<AxTaskRef> {
    debug!("clone_task with flags: {:?}", flags);
    let curr = current();
    let current_task_ext = curr.task_ext();
    const FLAG_MASK: u32 = 0xff;

    let exit_signal = flags.bits() & FLAG_MASK;
    if exit_signal != 0 && flags.contains(CloneFlags::THREAD | CloneFlags::PARENT) {
        return Err(LinuxError::EINVAL);
    }
    if flags.contains(CloneFlags::THREAD) && !flags.contains(CloneFlags::VM | CloneFlags::SIGHAND) {
        return Err(LinuxError::EINVAL);
    }

    let exit_signal = Signal::from_u32(exit_signal);
    // new task with same ip and sp of current task
    let mut trap_frame = read_trapframe_from_kstack(curr.get_kernel_stack_top().unwrap());

    let mut current_aspace = current_task_ext.process_data().aspace.clone();

    if from_umode {
        trap_frame.set_ret_code(0);
    }

    let child_tid_ref = if flags.contains(CloneFlags::CHILD_SETTID) {
        assert!(child_tid != 0);
        Some(unsafe { &mut *(child_tid as *mut u32)})
    } else {
        None
    };

    // TODO: clone stack since it's always changed.
    // stack is copied meanwhilst addr space is copied
    //trap_frame.set_user_sp(stack);
    if let Some(stack) = stack {
        trap_frame.set_user_sp(stack);
    }

    let mut new_uctx = UspaceContext::from(&trap_frame);
    if flags.contains(CloneFlags::SETTLS) {
        new_uctx.set_tls(tls);
    }

    let current_pwd = current_dir()?;
    let mut new_task = spawn_user_task_inner(curr.name(), new_uctx, current_pwd, child_tid_ref);
    let tid = new_task.id().as_u64() as Pid;

    if flags.contains(CloneFlags::PARENT_SETTID) {
        unsafe { ptr::write(parent_tid as *mut u32, tid) };
    }

    debug!("new process data");
    let process = if flags.contains(CloneFlags::THREAD) {
        new_task
            .ctx_mut()
            .set_page_table_root(current_aspace.lock().page_table_root());

        curr.task_ext().thread.process()
    } else {
        let parent = if flags.contains(CloneFlags::PARENT) {
            curr.task_ext()
                .thread
                .process()
                .parent()
                .ok_or(LinuxError::EINVAL)?
        } else {
            curr.task_ext().thread.process().clone()
        };
        let builder = parent.fork(tid);
        let aspace = if flags.contains(CloneFlags::VM) {
            current_aspace
        } else {
            #[cfg(feature = "COW")]
            let mut aspace = current_aspace.lock().clone_on_write()?;
            #[cfg(not(feature = "COW"))]
            let mut aspace = current_aspace.clone_or_err()?;
            copy_from_kernel(&mut aspace)?;
            Arc::new(Mutex::new(aspace))
        };

        new_task
            .ctx_mut()
            .set_page_table_root(aspace.lock().page_table_root());

        let signal = if flags.contains(CloneFlags::SIGHAND) {
            parent
                .data::<ProcessData>()
                .map_or_else(Arc::default, |it| it.signal.clone())
        } else {
            spawn_signal_ctx()
        };
        let process_data = ProcessData::new(
            curr.task_ext().process_data().exe_path.read().clone(),
            aspace,
            signal,
            exit_signal,
        );

        if flags.contains(CloneFlags::FILES) {
            FD_TABLE
                .deref_from(&process_data.ns)
                .init_shared(FD_TABLE.share());
        } else {
            FD_TABLE
                .deref_from(&process_data.ns)
                .init_new(FD_TABLE.copy_inner());
        }

        if flags.contains(CloneFlags::FS) {
            CURRENT_DIR
                .deref_from(&process_data.ns)
                .init_shared(CURRENT_DIR.share());
            CURRENT_DIR_PATH
                .deref_from(&process_data.ns)
                .init_shared(CURRENT_DIR_PATH.share());
        } else {
            CURRENT_DIR
                .deref_from(&process_data.ns)
                .init_new(CURRENT_DIR.copy_inner());
            CURRENT_DIR_PATH
                .deref_from(&process_data.ns)
                .init_new(CURRENT_DIR_PATH.copy_inner());
        }
        &builder.data(process_data).build()
    };

    let thread_data = ThreadData::new(process.data().unwrap());
    if flags.contains(CloneFlags::CHILD_CLEARTID) {
        thread_data.set_clear_child_tid(child_tid as usize);
    }

    let thread = process.new_thread(tid).data(thread_data).build();
    add_thread_to_table(&thread);
    new_task.init_task_ext(TaskExt::new(thread));
    Ok(axtask::spawn_task(new_task))
}

enum ExecType {
    Elf,
    Shebang(&'static str),
    Shell,
}

/// execve
/// mainly from starry
/// **Return**
/// - `Ok(handler)` if exec successfully, call handler to enter task.
/// - `Err(AxError)` if exec failed
///
pub fn exec_current(program_name: &str, args: &[String], envs: &[String]) -> AxResult<!> {
    warn!(
        "exec: {} with args {:?}, envs {:?}",
        program_name, args, envs
    );
    let mut args_ = vec![];
    let (oldpwd, pwd) = get_pwd_from_envs(envs);
    let mut program_path = axfs::path::canonicalize(program_name, pwd.as_ref().map(|s| s.as_str()));

    // 读取文件头部以检测类型
    let mut buffer: [u8; 64] = [0; 64];
    let mut file = axfs::api::File::open(program_path.as_str())?;
    file.read(&mut buffer)?;

    // 确定执行类型（ELF 或 Shell 脚本）
    let exec_type = if buffer.len() >= 4 && buffer[..4] == *b"\x7fELF" {
        ExecType::Elf
    } else if buffer[..2] == [b'#', b'!'] {
        ExecType::Shell
    } else {
        ExecType::Shell
    };

    // 加载 ELF 文件
    let elf_file: OwnedElfFile = match exec_type {
        ExecType::Elf => load_elf_from_disk(&program_path)
            .inspect_err(|err| debug!("load_elf_from_disk failed: {:?}", err))?,
        ExecType::Shell => {
            program_path = "/usr/bin/busybox".to_string();
            args_.push(program_path.clone());
            args_.push("sh".to_string());
            load_elf_from_disk(program_path.as_str()).unwrap()
        }
        _ => {
            unimplemented!()
        }
    };
    args_.extend_from_slice(args);

    let args_: &[String] = args_.as_slice();
    let current_task = current();

    // 检查地址空间是否被多个任务共享
    if Arc::strong_count(&current_task.task_ext().process_data().aspace) != 1 {
        warn!("Address space is shared by multiple tasks, exec is not supported.");
        return Err(AxError::Unsupported);
    }

    // 释放旧的用户地址空间映射
    let mut aspace = current_task.task_ext().process_data().aspace.lock();
    aspace.unmap_user_areas()?;
    axhal::arch::flush_tlb(None);

    // 使用之前定义的 load_elf_to_mem 函数加载 ELF 文件到内存
    let (entry_point, user_stack_base, thread_pointer) =
        load_elf_to_mem(elf_file, &mut aspace, Some(args_), Some(envs))?;

    axhal::arch::flush_tlb(None);

    unsafe { current_task.task_ext().process_data().aspace.force_unlock() };

    // 设置当前任务名称和目录
    current_task.set_name(&program_path);
    if let Some(pwd) = pwd {
        set_current_dir(pwd.as_str())?;
    }

    debug!(
        "exec: enter uspace, entry: {:?}, stack: {:?}",
        entry_point, user_stack_base,
    );

    // 设置用户上下文并进入用户空间
    let mut uctx = UspaceContext::new(entry_point.as_usize(), user_stack_base, 0);
    if let Some(tp) = thread_pointer {
        uctx.set_tp(tp.as_usize());
    }
    unsafe {
        uctx.enter_uspace(
            current_task
                .kernel_stack_top()
                .expect("No kernel stack top"),
        )
    }
}

/*
 *pub fn exec_current(program_name: &str, args: &[String], envs: &[String]) -> AxResult<!> {
 *    warn!(
 *        "exec: {} with args {:?}, envs {:?}",
 *        program_name, args, envs
 *    );
 *    let mut args_ = vec![];
 *    let (oldpwd, pwd) = get_pwd_from_envs(envs);
 *    let mut program_path = if let Some(ref pwd) = pwd {
 *        pwd.clone() + "/" + program_name
 *    } else {
 *        program_name.to_string()
 *    };
 *    // try reading shebang
 *    let mut buffer: [u8; 64] = [0; 64];
 *    let mut file = axfs::api::File::open(program_path.as_str())?;
 *    file.read(&mut buffer)?;
 *
 *    // FIXME: parse shebang
 *    let exec_type = if buffer.len() >= 4 && buffer[..4] == *b"\x7fELF" {
 *        ExecType::Elf
 *    } else if buffer[..2] == [b'#', b'!'] {
 *        // FIXME: read real shabang
 *        ExecType::Shell
 *    } else {
 *        ExecType::Shell
 *    };
 *
 *    let elf_file: OwnedElfFile = match exec_type {
 *        ExecType::Elf => load_elf_from_disk(&program_path)
 *            .inspect_err(|err| debug!("load_elf_from_disk failed: {:?}", err))?,
 *        ExecType::Shell => {
 *            // try reading shebang
 *            //debug!("execve:{:?} starts with shebang #!...", program_name);
 *            program_path = "/usr/bin/busybox".parse().unwrap(); // busybox
 *
 *            args_.push(program_path.clone().into());
 *            args_.push("ash".into());
 *
 *            load_elf_from_disk(program_path.as_str()).unwrap()
 *        }
 *        _ => {
 *            unimplemented!()
 *        }
 *    };
 *    args_.extend_from_slice(args);
 *
 *    let args_: &[String] = args_.as_slice();
 *    let current_task = current();
 *
 *    if Arc::strong_count(&current_task.task_ext().process_data().aspace) != 1 {
 *        warn!("Address space is shared by multiple tasks, exec is not supported.");
 *        return Err(AxError::Unsupported);
 *    }
 *    let mut aspace = current_task.task_ext().process_data().aspace.lock();
 *    let elf_info = ELFInfo::new(elf_file, aspace.base())?;
 *    aspace.unmap_user_areas()?;
 *    axhal::arch::flush_tlb(None);
 *
 *    //TODO: clone envs??
 *    let (entry_point, user_stack_base, thread_pointer) =
 *        map_elf_sections(elf_info, &mut aspace, Some(args_), Some(envs))?;
 *
 *    unsafe { current_task.task_ext().process_data().aspace.force_unlock() };
 *
 *    current_task.set_name(&program_path);
 *    if let Some(pwd) = pwd {
 *        set_current_dir(pwd.as_str())?;
 *    }
 *
 *    debug!(
 *        "exec: enter uspace, entry: {:?}, stack: {:?}",
 *        entry_point, user_stack_base,
 *    );
 *
 *    let mut uctx = UspaceContext::new(entry_point.as_usize(), user_stack_base, 0);
 *    if let Some(tp) = thread_pointer {
 *        uctx.set_tp(tp.as_usize());
 *    }
 *    unsafe {
 *        uctx.enter_uspace(
 *            current_task
 *                .kernel_stack_top()
 *                .expect("No kernel stack top"),
 *        )
 *    }
 *}
 */
