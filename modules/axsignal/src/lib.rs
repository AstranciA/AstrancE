#![feature(naked_functions)]
#![no_std]
#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate axlog;

extern crate alloc;

#[cfg(feature = "default_handler")]
mod default;
#[cfg(feature = "default_handler")]
pub use default::*;

use core::{
    arch::naked_asm,
    ffi::{c_int, c_void},
    fmt,
    mem::MaybeUninit,
    ops::Not,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    u64,
};

use alloc::boxed::Box;
use core::arch::asm;
use axerrno::{LinuxError, LinuxResult};
use axhal::arch::{TaskContext, TrapFrame, UspaceContext};
use bitflags::*;
use linux_raw_sys::general::*;
use memory_addr::{VirtAddr, VirtAddrRange};
use syscalls::Sysno;

const NSIG: usize = 64;
/// signals
#[repr(usize)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Signal {
    NONE = 0,
    //SIGBLOCK = SIG_BLOCK as usize,
    //SIGUNBLOCK = SIG_UNBLOCK,
    //SIGSETMASK = SIG_SETMASK,
    SIGHUP = SIGHUP as usize,
    SIGINT = SIGINT as usize,
    SIGQUIT = SIGQUIT as usize,
    SIGILL = SIGILL as usize,
    SIGTRAP = SIGTRAP as usize,
    //SIGABRT = SIGABRT,
    SIGIOT = SIGIOT as usize,
    SIGBUS = SIGBUS as usize,
    SIGFPE = SIGFPE as usize,
    SIGKILL = SIGKILL as usize,
    SIGUSR1 = SIGUSR1 as usize,
    SIGSEGV = SIGSEGV as usize,
    SIGUSR2 = SIGUSR2 as usize,
    SIGPIPE = SIGPIPE as usize,
    SIGALRM = SIGALRM as usize,
    SIGTERM = SIGTERM as usize,
    SIGSTKFLT = SIGSTKFLT as usize,
    SIGCHLD = SIGCHLD as usize,
    SIGCONT = SIGCONT as usize,
    SIGSTOP = SIGSTOP as usize,
    SIGTSTP = SIGTSTP as usize,
    SIGTTIN = SIGTTIN as usize,
    SIGTTOU = SIGTTOU as usize,
    SIGURG = SIGURG as usize,
    SIGXCPU = SIGXCPU as usize,
    SIGXFSZ = SIGXFSZ as usize,
    SIGVTALRM = SIGVTALRM as usize,
    SIGPROF = SIGPROF as usize,
    SIGWINCH = SIGWINCH as usize,
    SIGIO = SIGIO as usize,
    //SIGPOLL = SIGPOLL as usize,
    SIGPWR = SIGPWR as usize,
    //SIGSYS = SIGSYS as usize,
    SIGUNUSED = SIGUNUSED as usize,
}

//#[derive(Debug, Clone, Copy, PartialEq, Eq)]
//pub struct Signal(u32);
impl Signal {
    pub fn from_u32(n: u32) -> Option<Self> {
        if n as usize >= NSIG {
            None
        } else {
            Some(unsafe { core::mem::transmute(n as usize) })
        }
    }
}

impl TryFrom<c_int> for Signal {
    type Error = SignalError;

    fn try_from(value: c_int) -> Result<Self, Self::Error> {
        if value < 0 || value as usize > NSIG {
            Err(SignalError::InvalidSignal)
        } else {
            Ok(unsafe { core::mem::transmute(value as usize) })
        }
    }
}
impl Default for Signal {
    fn default() -> Self {
        Signal::NONE
    }
}
/*
 *impl Into<u32> for Signal {
 *    fn into(self) -> u32 {
 *        self as
 *    }
 *}
 *impl Into<u64> for Signal {
 *    fn into(self) -> u64 {
 *        self.0 as u64
 *    }
 *}
 */

bitflags! {
    #[derive(Clone, Copy, Default, Debug)]
    pub struct SignalSet :u64 {
        const SIGHUP     = 1 << (SIGHUP - 1);
        const SIGINT     = 1 << (SIGINT - 1);
        const SIGQUIT    = 1 << (SIGQUIT - 1);
        const SIGILL     = 1 << (SIGILL - 1);
        const SIGTRAP    = 1 << (SIGTRAP - 1);
        const SIGABRT    = 1 << (SIGABRT - 1);
        const SIGIOT     = 1 << (SIGIOT - 1);
        const SIGBUS     = 1 << (SIGBUS - 1);
        const SIGFPE     = 1 << (SIGFPE - 1);
        const SIGKILL    = 1 << (SIGKILL - 1);
        const SIGUSR1    = 1 << (SIGUSR1 - 1);
        const SIGSEGV    = 1 << (SIGSEGV - 1);
        const SIGUSR2    = 1 << (SIGUSR2 - 1);
        const SIGPIPE    = 1 << (SIGPIPE - 1);
        const SIGALRM    = 1 << (SIGALRM - 1);
        const SIGTERM    = 1 << (SIGTERM - 1);
        const SIGSTKFLT  = 1 << (SIGSTKFLT - 1);
        const SIGCHLD    = 1 << (SIGCHLD - 1);
        const SIGCONT    = 1 << (SIGCONT - 1);
        const SIGSTOP    = 1 << (SIGSTOP - 1);
        const SIGTSTP    = 1 << (SIGTSTP - 1);
        const SIGTTIN    = 1 << (SIGTTIN - 1);
        const SIGTTOU    = 1 << (SIGTTOU - 1);
        const SIGURG     = 1 << (SIGURG - 1);
        const SIGXCPU    = 1 << (SIGXCPU - 1);
        const SIGXFSZ    = 1 << (SIGXFSZ - 1);
        const SIGVTALRM  = 1 << (SIGVTALRM - 1);
        const SIGPROF    = 1 << (SIGPROF - 1);
        const SIGWINCH   = 1 << (SIGWINCH - 1);
        const SIGIO      = 1 << (SIGIO - 1);
        const SIGPOLL    = 1 << (SIGPOLL - 1);
        const SIGPWR     = 1 << (SIGPWR - 1);
        const SIGSYS     = 1 << (SIGSYS - 1);
        const SIGUNUSED  = 1 << (SIGUNUSED  - 1);
    }
}

impl SignalSet {
    /// get lowest signal in the set
    /// will return None if the set is empty (trailing_zeros == NSIG)
    pub fn get_one(&self) -> Option<Signal> {
        Signal::from_u32(self.bits().trailing_zeros() + 1)
    }

    /// get lowest signal in the set that is in the filter set
    /// will return None if no signal in the set is in the filter set
    pub fn get_one_in(&self, filter: SignalSet) -> Option<Signal> {
        Signal::from_u32(self.intersection(filter).bits().trailing_zeros() + 1)
    }

    /// take the lowest signal in the set and remove it from the set
    pub fn take_one(&mut self) -> Option<Signal> {
        if let Some(sig) = self.get_one() {
            self.remove(sig.into());
            Some(sig)
        } else {
            None
        }
    }

    /// take the lowest signal in the set that is in the filter set and remove it from the set
    pub fn take_one_in(&mut self, filter: SignalSet) -> Option<Signal> {
        if let Some(sig) = self.get_one_in(filter) {
            self.remove(sig.into());
            Some(sig)
        } else {
            None
        }
    }
}

impl From<Signal> for SignalSet {
    fn from(sig: Signal) -> Self {
        Self::from_bits_retain(1 << (sig as usize) - 1)
    }
}

impl TryFrom<SignalSet> for Signal {
    fn try_from(value: SignalSet) -> SignalResult<Self> {
        Signal::from_u32(value.bits().trailing_zeros() + 1).ok_or(SignalError::InvalidSignal)
    }

    type Error = SignalError;
}

#[cfg(any(target_arch = "riscv64", target_arch = "loongarch64"))]
impl From<sigset_t> for SignalSet {
    fn from(value: sigset_t) -> Self {
        Self::from_bits_retain(value.sig[0])
    }
}

bitflags! {
    /// 信号处理标志位，匹配POSIX标准和Linux扩展
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
        pub struct SigFlags: usize {
        /// 子进程停止时不发送SIGCHLD (SA_NOCLDSTOP)
        const NO_CHILD_STOP = SA_NOCLDSTOP as usize;
        /// 子进程退出时不成为僵尸进程 (SA_NOCLDWAIT)
        const NO_CHILD_WAIT = SA_NOCLDWAIT as usize;
        /// 使用三参数信号处理函数 (提供`siginfo_t`和上下文) (SA_SIGINFO)
        const SIG_INFO = SA_SIGINFO as usize;
        /// 被信号中断的系统调用自动重启 (SA_RESTART)
        const RESTART = SA_RESTART as usize;
        /// 使用备用信号栈 (通过`sigaltstack`设置) (SA_ONSTACK)
        const ON_STACK = SA_ONSTACK as usize;
        /// 不自动阻塞当前信号 (SA_NODEFER)
        const NO_DEFER = SA_NODEFER as usize;
        /// 执行处理程序后重置为默认处理 (SA_RESETHAND)
        const RESET_HAND = SA_RESETHAND as usize;
        /// 不自动重启系统调用 (历史遗留标志) (SA_INTERRUPT)
        const INTERRUPT = 0x2000_0000;
        /// 接收信号时通知ptrace (Linux特有) (SA_SIGINFO)
        const PT_TRACE = 0x0000_0020;
    }
}

#[derive(Debug, Clone, Copy)]
pub enum SigHandler {
    Ignore,
    Handler(unsafe extern "C" fn(c_int)),
    //actually Action(unsafe extern "C" fn(c_int, *mut siginfo_t, *mut c_void)),
    // this is for capabilites, since the fn won't be called directly
    Action(unsafe extern "C" fn(c_int)),
    Default(fn(Signal, &mut SignalContext)),
}

impl Default for SigHandler {
    fn default() -> Self {
        #[cfg(feature = "default_handler")]
        {
            Self::Default(handle_default_signal)
        }
        #[cfg(not(feature = "default_handler"))]
        {
            Self::Ignore
        }
    }
}

/*
 *impl fmt::Debug for SigHandler {
 *    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
 *        match self {
 *            SigHandler::Default(_) => write!(f, "SigHandler::Default(<closure>)"),
 *            SigHandler::Ignore => write!(f, "SigHandler::Ignore"),
 *            SigHandler::Handler(fn_) => write!(f, "SigHandler::Handler({:p})", fn_),
 *            SigHandler::Action(fn_) => write!(f, "SigHandler::Action({:p})", fn_),
 *        }
 *    }
 *}
 *
 *impl Clone for SigHandler {
 *    fn clone(&self) -> Self {
 *        match *self {
 *            SigHandler::Default(fn_) => SigHandler::Default(fn_),
 *            SigHandler::Ignore => SigHandler::Ignore,
 *            SigHandler::Handler(h) => SigHandler::Handler(h),
 *            SigHandler::Action(a) => SigHandler::Action(a),
 *            SigHandler::Custom(_) => SigHandler::Custom(Box::new(|sig, ctx| { [> Default action <] })),
 *        }
 *    }
 *}
 */

#[derive(Default, Clone, Copy, Debug)]
/// 信号动作配置
pub struct SigAction {
    pub handler: SigHandler,
    pub mask: SignalSet,
    pub flags: SigFlags,
}

#[cfg(any(target_arch = "riscv64", target_arch = "loongarch64"))]
impl TryFrom<sigaction> for SigAction {
    type Error = SignalError;

    fn try_from(act: sigaction) -> Result<Self, Self::Error> {
        /*
         *let flags = if let Some(flags) = SigFlags::from_bits(act.sa_flags.try_into().unwrap()) {
         *    flags
         *} else {
         *    return Err(SignalError::InvalidFlags);
         *};
         */
        let flags = SigFlags::from_bits_retain(act.sa_flags as usize);
        let mask = act.sa_mask.into();
        let handler = if let Some(sa_handler) = act.sa_handler {
            if flags.contains(SigFlags::SIG_INFO) {
                SigHandler::Handler(sa_handler)
            } else {
                SigHandler::Action(sa_handler)
            }
        } else {
            // FIXME: using kernel provided default

            #[cfg(feature = "default_handler")]
            {
                SigHandler::Default(default_signal_handler)
            }
            #[cfg(not(feature = "default_handler"))]
            {
                SigHandler::Default(|signal, _| {
                    error!("Unassigned default handler for signal {signal:?}")
                })
            }
        };

        Ok(Self {
            handler,
            mask,
            flags,
        })
    }
}

impl Into<sigaction> for SigAction {
    fn into(self) -> sigaction {
        // 初始化一个全零的sigaction（避免未初始化字段）
        let mut act: sigaction = unsafe { MaybeUninit::zeroed().assume_init() };

        // 1. 设置处理函数联合体
        unsafe {
            match self.handler {
                SigHandler::Handler(f) => {
                    act.sa_handler = Some(f);
                }
                SigHandler::Action(f) => {
                    act.sa_handler = Some(f);
                }
                SigHandler::Default(_) => {
                    act.sa_handler = None;
                }
                SigHandler::Ignore => {
                    act.sa_handler = Some(core::mem::transmute(SIG_IGN));
                }
            }
        }

        // 2. 设置信号掩码（RISC-V使用单个u64）
        act.sa_mask = unsafe { core::mem::transmute(self.mask.bits()) };

        // 3. 设置标志位
        act.sa_flags = self.flags.bits() as u64;

        // 4. RISC-V不需要显式restorer，但保持ABI兼容
        // act.sa_restorer = None;

        act
    }
}

pub const SIG_DFL: usize = 0;
pub const SIG_IGN: usize = 1;

unsafe extern "C" fn tmp(a: i32) {}

#[naked]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".trampoline.sigreturn")]
#[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
pub unsafe extern "C" fn sigreturn_trampoline() {
    // 内联汇编确保无函数前导/后导代码
    naked_asm!(
        "li a7, {sysno}",
        "ecall",
        sysno = const Sysno::rt_sigreturn as usize,
    );
}

#[naked]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".trampoline.sigreturn")]
#[cfg(target_arch = "loongarch64")]
pub unsafe extern "C" fn sigreturn_trampoline() {
    naked_asm!(
    "li.d $a7, {sysno}", // 将系统调用号加载到 a7 寄存器
    "syscall 0",
    sysno = const Sysno::rt_sigreturn as usize,
    );
}


// 进程信号上下文
pub struct SignalContext {
    stack: SignalFrameManager,
    actions: [SigAction; NSIG], // 信号处理表
    blocked: SignalSet,         // 被阻塞的信号
    pending: SignalSet,         // 待处理信号
}

impl Default for SignalContext {
    fn default() -> Self {
        let mut default = Self {
            stack: Default::default(),
            actions: [Default::default(); NSIG],
            blocked: Default::default(),
            pending: Default::default(),
        };
        #[cfg(feature = "default_handler")]
        {
            set_default_handlers(&mut default);
        }
        default
    }
}

impl SignalContext {
    /// 向进程发送信号
    pub fn send_signal(&mut self, sig: SignalSet) {
        debug!(
            "send signal: {:?}, pending: {:?}, blocked: {:?}",
            sig, self.pending, self.blocked
        );
        self.pending = self.pending.union(sig);
    }

    /// 检查是否有待处理信号
    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    /// 获取信号处理动作，返回之前的动作
    pub fn get_action(&mut self, sig: Signal) -> &SigAction {
        &self.actions[sig as usize]
    }
    /// 设置信号处理动作，返回之前的动作
    pub fn set_action(&mut self, sig: Signal, act: SigAction) -> SigAction {
        trace!("set action: {act:?}");
        let old_act = self.actions[sig as usize];
        self.actions[sig as usize] = act;
        old_act
    }

    pub fn set_current_stack(&mut self, ty: SignalStackType) -> Option<&mut SignalFrame> {
        self.stack.switch_to(ty)
    }

    pub fn current_frame(&mut self) -> SignalResult<&mut SignalFrame> {
        self.stack.current_frame().ok_or(SignalError::NoStack)
    }

    pub fn set_stack(&mut self, ty: SignalStackType, range: VirtAddrRange) {
        self.stack.set_stack(ty, range);
    }

    pub fn get_blocked(&self) -> SignalSet {
        self.blocked
    }

    pub fn get_pending(&self) -> SignalSet {
        self.pending
    }

    pub fn deliver_one(&mut self) -> Option<Signal> {
        self.pending
            .take_one_in(self.blocked.not())
            .inspect(|sig| debug!("deliver signal: {:?}", sig))
    }

    pub fn consume_one(&mut self) -> Option<Signal> {
        self.pending
            .take_one()
            .inspect(|sig| debug!("consume signal: {:?}", sig))
    }

    pub fn consume_one_in(&mut self, filter: SignalSet) -> Option<Signal> {
        self.pending
            .take_one_in(filter)
            .inspect(|sig| debug!("consume signal: {:?}", sig))
    }

    /*
     *pub fn take_pending_in(&mut self, filter: SignalSet) -> Option<Signal> {
     *    self.pending.take_one_in(filter)
     *}
     */

    pub fn block(&mut self, mask: SignalSet) -> SignalSet {
        let old = self.blocked;
        self.blocked = self.blocked.union(mask);
        old
    }

    pub fn unblock(&mut self, mask: SignalSet) -> SignalSet {
        let old = self.blocked;
        self.blocked = self.blocked.difference(mask);
        old
    }

    pub fn set_mask(&mut self, mask: SignalSet) -> SignalSet {
        let old = self.blocked;
        self.blocked = mask;
        old
    }

    /// 加载当前信号栈帧，返回之前的sscratch
    /// 用户不能手动调用
    fn load(&mut self, scratch: usize, data: SignalFrameData) -> SignalResult<usize> {
        let curr_frame = self.current_frame()?;
        curr_frame.load(scratch, data)?;
        Ok(curr_frame.scratch(scratch))
    }

    /// 释放当前信号栈帧，恢复blocked，返回原scratch(原陷入栈)，必须和load成对
    /// 用户需要在sigreturn中手动调用
    pub fn unload(&mut self) -> SignalResult<(usize, TrapFrame)> {
        let curr_frame = self.current_frame()?;
        let (
            SignalFrameData {
                signal,
                uc_sigmask,
                orig_frame,
                ..
            },
            trap_frame,
        ) = curr_frame.unload()?;
        self.blocked = uc_sigmask;
        self.pending.remove(signal.into());
        Ok((trap_frame, orig_frame))
    }
}

#[derive(Debug, Clone, Copy)]
pub enum SignalError {
    NoStack,            // 信号栈不可用
    StackNotLoaded,     // 信号栈已初始化
    StackAlreadyLoaded, // 信号栈已初始化
    SigNotImpl,         // 信号未实现
    InvalidAction,      // 无效的处理动作
    InvalidFlags,       // 无效的标志位组合
    InvalidSignal,      // 无效的信号编号
    PermissionDenied,   // 权限不足(如设置SIGKILL)
}
impl From<SignalError> for LinuxError {
    fn from(err: SignalError) -> LinuxError {
        match err {
            SignalError::NoStack => LinuxError::ENOMEM, // 无内存用于信号栈
            SignalError::SigNotImpl => LinuxError::ENOSYS, // 功能未实现
            SignalError::InvalidAction => LinuxError::EINVAL, // 无效参数
            SignalError::InvalidFlags => LinuxError::EINVAL, // 无效标志
            SignalError::InvalidSignal => LinuxError::EINVAL, // 无效信号号
            SignalError::PermissionDenied => LinuxError::EPERM,
            _ => panic!("{err:?}"),
        }
    }
}

type SignalResult<T> = Result<T, SignalError>;
#[derive(Clone, Copy)]
pub enum SignalStackType {
    Primary = 0,   // 主线程栈
    Alternate = 1, // 用户指定的备用栈
    Emergency = 2, // 内核紧急栈（只用于同步信号）
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SignalFrameData {
    pub signal: Signal,
    pub uc_sigmask: SignalSet,
    pub sigmask: SignalSet,
    pub flags: SigFlags,
    pub orig_frame: TrapFrame,
}

#[derive(Debug)]
pub struct SignalFrame {
    loaded: AtomicBool,
    range: VirtAddrRange,
    scratch: AtomicUsize,
    data: SignalFrameData,
}

impl SignalFrame {
    // TODO: check align
    pub fn set_stack(&mut self, range: VirtAddrRange) {
        self.range = range;
    }

    pub fn range(&self) -> VirtAddrRange {
        self.range
    }

    pub fn ptr(&self) -> VirtAddr {
        self.range.end
    }
    pub fn size(&self) -> usize {
        self.range.size()
    }

    fn scratch(&mut self, scratch: usize) -> usize {
        self.scratch
            .swap(scratch, core::sync::atomic::Ordering::SeqCst)
    }

    // 准备作为信号处理栈帧，返回之前的scratch, 一般是0
    fn load(&mut self, scratch: usize, data: SignalFrameData) -> SignalResult<usize> {
        self.loaded
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
            .map_err(|_| SignalError::StackAlreadyLoaded)?;
        self.data = data;
        Ok(self.scratch(scratch))
    }

    // 释放当前的信号处理帧，返回处理函数和原scratch(原陷入栈)，必须和load成对
    fn unload(&mut self) -> SignalResult<(SignalFrameData, usize)> {
        self.loaded
            .compare_exchange(true, false, Ordering::AcqRel, Ordering::Relaxed)
            .map_err(|_| SignalError::StackNotLoaded)?;
        // 原栈指针被抛弃，恢复信号处理前原来的上下文
        let scratch = self.scratch(0);
        Ok((self.data, scratch))
    }
}

impl Default for SignalFrame {
    fn default() -> Self {
        Self {
            loaded: AtomicBool::new(false),
            range: Default::default(),
            scratch: Default::default(),
            data: Default::default(),
        }
    }
}

pub struct SignalFrameManager {
    frames: [Option<SignalFrame>; 3],
    current: SignalStackType,
    /// For saving/restoring previous stack
    scratch: AtomicUsize,
}

impl SignalFrameManager {
    pub fn current_frame(&mut self) -> Option<&mut SignalFrame> {
        self.frames[self.current as usize].as_mut()
    }

    pub fn set_stack(&mut self, ty: SignalStackType, range: VirtAddrRange) {
        if let Some(stack) = self.frames[ty as usize].as_mut() {
            stack.set_stack(range);
        } else {
            self.frames[ty as usize] = Some(SignalFrame {
                range,
                ..Default::default()
            });
        }
    }
}

impl Default for SignalFrameManager {
    fn default() -> Self {
        Self {
            frames: [const { None }; 3],
            current: SignalStackType::Primary,
            scratch: AtomicUsize::new(0),
        }
    }
}

impl SignalFrameManager {
    fn switch_to(&mut self, ty: SignalStackType) -> Option<&mut SignalFrame> {
        // TODO: 可以在栈被加载的时候切换吗？
        // handle scratch?
        self.current = ty;
        self.frames[ty as usize].as_mut()
    }
}

/// 处理信号，需要提前设置信号栈
/*pub fn handle_pending_signals(
    sigctx: &mut SignalContext,
    thread_tf: &TrapFrame,
    trampoline: VirtAddr,
) -> SignalResult<Option<(UspaceContext, VirtAddr)>> {
    while let Some(sig) = sigctx.deliver_one() {
        // 找到最高优先级的待处理信号
        debug!("handle signal: {sig:?}");
        let old_mask = (*sigctx).blocked;
        let action = *sigctx.get_action(sig);
        let SigAction {
            handler,
            mask: act_mask,
            flags,
        } = action;
        debug!("handler: {handler:?}, action_mask: {act_mask:?}, flags: {flags:?}");

        match handler {
            SigHandler::Default(f) => f(sig, &mut *sigctx),
            SigHandler::Ignore => {} // 直接忽略
            SigHandler::Handler(handler) => {
                // 设置信号处理栈帧
                let mask = old_mask.union(act_mask);
                (*sigctx).blocked = mask;
                assert_eq!(
                    sigctx.load(unsafe { axhal::arch::read_trap_frame() }, SignalFrameData {
                        signal: sig,
                        uc_sigmask: old_mask,
                        sigmask: mask,
                        flags: flags,
                        orig_frame: *thread_tf,
                    })?,
                    0,
                    "signal stack scratch is not empty"
                );
                let current_frame: &mut SignalFrame = sigctx.current_frame()?;
                let kstack_top = current_frame.ptr();
                // 在syscall rt_sigreturn中清除信号。
                let mut uctx =
                    UspaceContext::new(handler as usize, thread_tf.get_sp().into(), sig as usize);
                uctx.0.regs.tp = thread_tf.regs.tp;
                uctx.0.regs.gp = thread_tf.regs.gp;
                // 设置返回地址为信号返回trampoline
                uctx.0.set_ra(trampoline.as_usize());

                return Ok(Some((uctx, kstack_top)));
            }
            SigHandler::Action(handler) => {
                error!("sig action argument not implemented");
                // 设置信号处理栈帧
                let mask = old_mask.union(act_mask);
                (*sigctx).blocked = mask;
                assert_eq!(
                    sigctx.load(unsafe { axhal::arch::read_trap_frame() }, SignalFrameData {
                        signal: sig,
                        uc_sigmask: old_mask,
                        sigmask: mask,
                        flags: flags,
                        orig_frame: *thread_tf,
                    })?,
                    0,
                    "signal stack scratch is not empty"
                );
                let current_frame: &mut SignalFrame = sigctx.current_frame()?;
                let kstack_top = current_frame.ptr();
                // 在syscall rt_sigreturn中清除信号。
                let mut uctx =
                    UspaceContext::new(handler as usize, thread_tf.get_sp().into(), sig as usize);
                uctx.0.regs.tp = thread_tf.regs.tp;
                uctx.0.regs.gp = thread_tf.regs.gp;
                // 设置返回地址为信号返回trampoline
                uctx.0.set_ra(trampoline.as_usize());

                return Ok(Some((uctx, kstack_top)));
            }
        };

        sigctx.blocked = old_mask;
    }
    Ok(None)
}*/

pub fn handle_pending_signals(
    sigctx: &mut SignalContext,
    thread_tf: &TrapFrame,
    trampoline: VirtAddr,
) -> SignalResult<Option<(UspaceContext, VirtAddr)>> {
    while let Some(sig) = sigctx.pending.take_one() {
        // 找到最高优先级的待处理信号
        debug!("handle signal: {sig:?}");
        let old_mask = (*sigctx).blocked;
        let action = *sigctx.get_action(sig);
        let SigAction {
            handler,
            mask: act_mask,
            flags,
        } = action;
        warn!("handler: {handler:?}, action_mask: {act_mask:?}, flags: {flags:?}");

        match handler {
            SigHandler::Default(f) => f(sig, &mut *sigctx),
            SigHandler::Ignore => {} // 直接忽略
            SigHandler::Handler(handler) => {
                // 设置信号处理栈帧
                let mask = old_mask.union(act_mask);
                (*sigctx).blocked = mask;
                assert_eq!(
                    sigctx.load(
                        unsafe { axhal::arch::read_trap_frame() },
                        SignalFrameData {
                            signal: sig,
                            uc_sigmask: old_mask,
                            sigmask: mask,
                            flags: flags,
                            orig_frame: *thread_tf,
                        }
                    )?,
                    0,
                    "signal stack scratch is not empty"
                );
                let current_frame: &mut SignalFrame = sigctx.current_frame()?;
                let kstack_top = current_frame.ptr();
                // 在syscall rt_sigreturn中清除信号。
                let mut uctx = {
                    #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
                    {
                        UspaceContext::new(
                            handler as usize,
                            thread_tf.get_sp().into(),
                            sig as usize,
                        )
                    }
                    #[cfg(target_arch = "loongarch64")]
                    {
                        UspaceContext::new(
                            handler as usize,
                            thread_tf.get_user_sp().into(),
                            sig as usize,
                        )
                    }
                };
                // 设置线程本地存储和全局指针
                uctx.0.regs.tp = thread_tf.regs.tp;
                #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
                {
                    uctx.0.regs.gp = thread_tf.regs.gp;
                }
                // 设置返回地址为信号返回trampoline
                uctx.0.set_ra(trampoline.as_usize());

                return Ok(Some((uctx, kstack_top)));
            }
            SigHandler::Action(handler) => {
                // 设置信号处理栈帧
                let mask = old_mask.union(act_mask);
                (*sigctx).blocked = mask;
                assert_eq!(
                    sigctx.load(
                        unsafe { axhal::arch::read_trap_frame() },
                        SignalFrameData {
                            signal: sig,
                            uc_sigmask: old_mask,
                            sigmask: mask,
                            flags: flags,
                            orig_frame: *thread_tf,
                        }
                    )?,
                    0,
                    "signal stack scratch is not empty"
                );
                let current_frame: &mut SignalFrame = sigctx.current_frame()?;
                let kstack_top = current_frame.ptr();
                // 在syscall rt_sigreturn中清除信号。
                let mut uctx = {
                    #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
                    {
                        UspaceContext::new(
                            handler as usize,
                            thread_tf.get_sp().into(),
                            sig as usize,
                        )
                    }
                    #[cfg(target_arch = "loongarch64")]
                    {
                        UspaceContext::new(
                            handler as usize,
                            thread_tf.get_user_sp().into(),
                            sig as usize,
                        )
                    }
                };
                // 设置线程本地存储和全局指针
                uctx.0.regs.tp = thread_tf.regs.tp;
                #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
                {
                    uctx.0.regs.gp = thread_tf.regs.gp;
                }
                // 设置返回地址为信号返回trampoline
                uctx.0.set_ra(trampoline.as_usize());

                return Ok(Some((uctx, kstack_top)));
            }
        };

        sigctx.blocked = old_mask;
    }
    Ok(None)
}


fn handle_default_signal(sig: Signal, ctx: &mut SignalContext) {
    #[cfg(feature = "default_handler")]
    {
        default_signal_handler(sig, ctx);
    }
    #[cfg(not(feature = "default_handler"))]
    {
        warn!("Unhandled default signal: {sig:?}")
    }
}
