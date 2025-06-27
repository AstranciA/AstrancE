use core::{ffi::c_void, ptr};

use linux_raw_sys::general::*;
use memory_addr::VirtAddr;
use numeric_enum_macro::numeric_enum;

use crate::Signal;

pub type Fd = i32;
pub type Band = i64; // For si_band, often long
pub type ErrNum = i32;
pub type Uid = u32;
pub type Pid = i32;

numeric_enum! {
    #[repr(i32)]
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    pub enum SigCodeCommon {
        SI_USER = SI_USER as i32,
        SI_KERNEL = SI_KERNEL as i32,
        SI_QUEUE = SI_QUEUE as i32,
        SI_TIMER = SI_TIMER as i32,
        SI_MESGQ = SI_MESGQ as i32,
        SI_ASYNCIO = SI_ASYNCIO as i32,
        SI_SIGIO = SI_SIGIO as i32,
        //SI_LWP = SI_LWP as i32,
    }
}
numeric_enum! {
    #[repr(i32)]
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    pub enum SigCodeSigChld {
        CLD_EXITED = CLD_EXITED as i32,
        CLD_KILLED = CLD_KILLED as i32,
        CLD_DUMPED = CLD_DUMPED as i32,
        CLD_TRAPPED = CLD_TRAPPED as i32, // 检查这个值是否与其他 SigCodeSigChld 冲突
        CLD_STOPPED = CLD_STOPPED as i32,
        CLD_CONTINUED = CLD_CONTINUED as i32,
    }
}
numeric_enum! {
    #[repr(i32)]
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    pub enum SigCodeSigSegv {
        SEGV_MAPERR = SEGV_MAPERR as i32,
        SEGV_ACCERR = SEGV_ACCERR as i32,
        SEGV_BNDERR = SEGV_BNDERR as i32,
        SEGV_PKUERR = SEGV_PKUERR as i32, // 检查这个值是否与其他 SigCodeSigSegv 冲突
    }
}
numeric_enum! {
    #[repr(i32)]
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    pub enum SigCodeSigBus {
        BUS_ADRALN = BUS_ADRALN as i32,
        BUS_ADRERR = BUS_ADRERR as i32,
        BUS_OBJERR = BUS_OBJERR as i32,
        BUS_MCEERR_AR = BUS_MCEERR_AR as i32, // 检查这个值是否与其他 SigCodeSigBus 冲突
        BUS_MCEERR_AO = BUS_MCEERR_AO as i32,
    }
}
numeric_enum! {
    #[repr(i32)]
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    pub enum SigCodeSigFpe {
        FPE_INTDIV = FPE_INTDIV as i32,
        FPE_INTOVF = FPE_INTOVF as i32,
        FPE_FLTDIV = FPE_FLTDIV as i32,
        FPE_FLTOVF = FPE_FLTOVF as i32, // 检查这个值是否与其他 SigCodeSigFpe 冲突
        FPE_FLTUND = FPE_FLTUND as i32,
        FPE_FLTRES = FPE_FLTRES as i32,
        FPE_FLTINV = FPE_FLTINV as i32,
        FPE_FLTSUB = FPE_FLTSUB as i32,
    }
}
numeric_enum! {
    #[repr(i32)]
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    pub enum SigCodeSigIll {
        ILL_ILLOPC = ILL_ILLOPC as i32,
        ILL_ILLOPN = ILL_ILLOPN as i32,
        ILL_ILLADR = ILL_ILLADR as i32,
        ILL_ILLTRP = ILL_ILLTRP as i32, // 检查这个值是否与其他 SigCodeSigIll 冲突
        ILL_PRVOPC = ILL_PRVOPC as i32,
        ILL_PRVREG = ILL_PRVREG as i32,
        ILL_COPROC = ILL_COPROC as i32,
        ILL_BADSTK = ILL_BADSTK as i32,
    }
}
numeric_enum! {
    #[repr(i32)]
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    pub enum SigCodeSigTrap {
        TRAP_BRKPT = TRAP_BRKPT as i32,
        TRAP_TRACE = TRAP_TRACE as i32,
        // TRAP_BRANCH = 3, // 如果有，也要加入
        // TRAP_HWBKPT = 4, // 如果有，也要加入
    }
}
numeric_enum! {
    #[repr(i32)]
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    pub enum SigCodeSigPoll {
        POLL_IN = POLL_IN as i32,
        POLL_OUT = POLL_OUT as i32,
        POLL_MSG = POLL_MSG as i32,
        POLL_ERR = POLL_ERR as i32, // 检查这个值是否与其他 SigCodeSigPoll 冲突
        POLL_PRI = POLL_PRI as i32,
        POLL_HUP = POLL_HUP as i32,
    }
}
numeric_enum! {
    #[repr(i32)]
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    pub enum SigCodeSigSys {
        SYS_SECCOMP = SYS_SECCOMP as i32,
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum SigCode {
    Common(SigCodeCommon),
    SigChld(SigCodeSigChld),
    SigSegv(SigCodeSigSegv),
    SigBus(SigCodeSigBus),
    SigFpe(SigCodeSigFpe),
    SigIll(SigCodeSigIll),
    SigTrap(SigCodeSigTrap),
    SigPoll(SigCodeSigPoll),
    SigSys(SigCodeSigSys),
    // 可以添加一个 Unknown 变体，用于处理无法分类的代码
    UnknownCode(i32),
}

impl From<SigCode> for i32 {
    fn from(code: SigCode) -> Self {
        match code {
            SigCode::Common(c) => c as i32,
            SigCode::SigChld(c) => c as i32,
            SigCode::SigSegv(c) => c as i32,
            SigCode::SigBus(c) => c as i32,
            SigCode::SigFpe(c) => c as i32,
            SigCode::SigIll(c) => c as i32,
            SigCode::SigTrap(c) => c as i32,
            SigCode::SigPoll(c) => c as i32,
            SigCode::SigSys(c) => c as i32,
            SigCode::UnknownCode(val) => val, // 对于未知代码，直接返回其值
        }
    }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigStatus {
    /// 当 `si_code` 为 `CLD_EXITED` 时，`si_status` 表示子进程的退出码。
    ExitCode(i32),
    /// 当 `si_code` 为 `CLD_KILLED` 或 `CLD_DUMPED` 时，`si_status` 表示导致子进程终止的信号编号。
    TerminatingSignal(i32),
    /// 当 `si_code` 为 `CLD_STOPPED` 或 `CLD_CONTINUED` 时，`si_status` 表示导致子进程停止或继续的信号编号。
    StoppingOrContinuingSignal(i32),
    /// 对于其他 `si_code`，`si_status` 可能没有明确的通用含义，或者不适用。
    /// 在这种情况下，我们只存储原始的 `i32` 值。
    RawStatus(i32),
}


impl SigStatus {
    /// 从 `si_code` 和原始 `si_status` 值创建 `SiStatusMeaning`。
    pub fn from_raw(si_code: u32, raw_status: i32) -> Self {
        match si_code {
            CLD_EXITED => SigStatus::ExitCode(raw_status),
            CLD_KILLED | CLD_DUMPED => SigStatus::TerminatingSignal(raw_status),
            CLD_STOPPED | CLD_CONTINUED => SigStatus::StoppingOrContinuingSignal(raw_status),
            _ => SigStatus::RawStatus(raw_status),
        }
    }
    /// 获取原始的 `i32` 状态值。
    pub fn as_raw_i32(&self) -> i32 {
        match self {
            SigStatus::ExitCode(val) => *val,
            SigStatus::TerminatingSignal(val) => *val,
            SigStatus::StoppingOrContinuingSignal(val) => *val,
            SigStatus::RawStatus(val) => *val,
        }
    }
}

/// 包含 siginfo_t 联合体中不同信号类型的数据
#[derive(Debug, Clone, Copy)]
pub enum SigInfoData {
    /// 通用信号，例如由 kill() 或 raise() 发送
    Generic { pid: Pid, uid: Uid },
    /// 子进程状态改变 (SIGCHLD)
    Child {
        pid: Pid,
        uid: Uid,
        status: SigStatus, // 退出状态或终止信号
        utime: u64,        // 用户 CPU 时间 (Linux 特有)
        stime: u64,        // 系统 CPU 时间 (Linux 特有)
    },
    /// 内存访问错误 (SIGSEGV, SIGBUS)
    MemoryAccess {
        addr: VirtAddr, // 导致错误的地址
                        // trapno: i32, // 陷阱编号，如果需要可以添加
    },
    /// 算术错误 (SIGFPE)
    FPEError {
        addr: VirtAddr, // 导致错误的指令地址
    },
    /// 非法指令 (SIGILL)
    IllegalInstruction {
        addr: VirtAddr, // 导致错误的指令地址
    },
    /// 总线错误 (SIGBUS)
    BusError {
        addr: VirtAddr, // 导致错误的地址
    },
    /// 实时信号 (sigqueue)
    Realtime {
        value: i32,    // 携带的整数值
        ptr: VirtAddr, // 携带的指针值
    },
    /// I/O 事件 (SIGPOLL/SIGIO)
    PollIO { fd: Fd, band: Band },
    /// 系统调用错误 (SIGSYS)
    SyscallError {
        call_addr: VirtAddr, // 导致错误的系统调用地址
        syscall_num: u32,    // 错误的系统调用号
        arch: u32,           // 错误的系统调用架构
    },
    /// 其他或无额外数据
    None,
}

/// 模拟 C 语言的 siginfo_t 结构体
/// 这是一个 Rust 友好的表示，便于在内核中构建和传递信息
#[derive(Debug, Clone, Copy)]
pub struct SigInfo {
    pub signo: Signal,
    pub errno: ErrNum,
    pub code: SigCode,
    pub data: SigInfoData,
}
impl SigInfo {
    /// 创建一个通用的 SigInfo 实例
    pub fn new_generic(signo: Signal, code: SigCodeCommon, pid: Pid, uid: Uid) -> Self {
        SigInfo {
            signo,
            errno: 0, // 默认无错误
            code: SigCode::Common(code),
            data: SigInfoData::Generic { pid, uid },
        }
    }
    /// 创建一个 SIGCHLD 相关的 SigInfo 实例
    pub fn new_child(
        signo: Signal,
        code: SigCodeSigChld,
        pid: Pid,
        uid: Uid,
        status: SigStatus,
        utime: u64,
        stime: u64,
    ) -> Self {
        SigInfo {
            signo,
            errno: 0,
            code:SigCode::SigChld(code),
            data: SigInfoData::Child {
                pid,
                uid,
                status,
                utime,
                stime,
            },
        }
    }
    /// 创建一个内存访问错误相关的 SigInfo 实例 (SIGSEGV, SIGBUS)
    pub fn new_memory_access(signo: Signal, code: SigCode, addr: VirtAddr) -> Self {
        SigInfo {
            signo,
            errno: 0,
            code,
            data: SigInfoData::MemoryAccess { addr },
        }
    }
    /// 创建一个实时信号相关的 SigInfo 实例
    pub fn new_realtime(signo: Signal, code: SigCode, value: i32, ptr: VirtAddr) -> Self {
        SigInfo {
            signo,
            errno: 0,
            code,
            data: SigInfoData::Realtime { value, ptr },
        }
    }
    /// 创建一个 I/O 事件相关的 SigInfo 实例
    pub fn new_poll_io(signo: Signal, code: SigCode, fd: Fd, band: Band) -> Self {
        SigInfo {
            signo,
            errno: 0,
            code,
            data: SigInfoData::PollIO { fd, band },
        }
    }
    /// 创建一个没有额外数据的 SigInfo 实例 (例如 SIGKILL, SIGSTOP)
    pub fn new_simple(signo: Signal, code: SigCode) -> Self {
        SigInfo {
            signo,
            errno: 0,
            code,
            data: SigInfoData::None,
        }
    }

    pub unsafe fn fill_raw_siginfo(&self, raw_siginfo: &mut siginfo_t) {
        // 首先清零整个结构体，以避免未初始化的字段导致的问题
        // 这对于包含 union 的结构体尤其重要
        unsafe {
            ptr::write_bytes(
                raw_siginfo as *mut _ as *mut u8,
                0,
                core::mem::size_of::<siginfo_t>(),
            )
        };
        let mut siginfo_ = unsafe { &mut raw_siginfo.__bindgen_anon_1.__bindgen_anon_1 };
        siginfo_.si_signo = self.signo as usize as i32;
        siginfo_.si_errno = self.errno;
        siginfo_.si_code = i32::from(self.code); // SigCode 枚举直接转换为 i32
        let mut sifields = &mut siginfo_._sifields;
        // 根据 SigInfoData 的类型填充 union 字段
        match &self.data {
            SigInfoData::Generic { pid, uid } => {
                sifields._kill._pid = *pid;
                sifields._kill._uid = *uid;
            }
            SigInfoData::Child {
                pid,
                uid,
                status,
                utime,
                stime,
            } => {
                sifields._sigchld._uid = *uid;
                sifields._sigchld._pid = *pid;
                sifields._sigchld._stime = *stime as i64;
                sifields._sigchld._utime = *utime as i64;
                sifields._sigchld._status = status.as_raw_i32();
            }
            SigInfoData::MemoryAccess { addr } => {
                sifields._sigfault._addr = unsafe { addr.as_ptr() } as *mut c_void;
                // TODO:
                //sifields._sigfault.__bindgen_anon_1;
            }
            SigInfoData::FPEError { addr } => {
                sifields._sigfault._addr = unsafe { addr.as_ptr() } as *mut c_void;
            }
            SigInfoData::IllegalInstruction { addr } => {
                sifields._sigfault._addr = unsafe { addr.as_ptr() } as *mut c_void;
            }
            SigInfoData::BusError { addr } => {
                sifields._sigfault._addr = unsafe { addr.as_ptr() } as *mut c_void;
            }
            SigInfoData::Realtime { value, ptr } => {
                sifields._rt._pid = 0; // 可能需要根据实际情况设置
                sifields._rt._uid = 0; // 可能需要根据实际情况设置
                sifields._rt._sigval.sival_int = *value;
                sifields._rt._sigval.sival_ptr = unsafe { ptr.as_ptr() } as *mut c_void;
            }
            SigInfoData::PollIO { fd, band } => {
                sifields._sigpoll._fd = *fd;
                sifields._sigpoll._band = *band;
            }
            SigInfoData::SyscallError {
                call_addr,
                syscall_num,
                arch,
            } => {
                sifields._sigsys._call_addr = call_addr.as_ptr() as *mut c_void;
                sifields._sigsys._syscall = *syscall_num as i32;
                sifields._sigsys._arch = *arch;
            }
            SigInfoData::None => {
                // 对于没有额外数据的信号，union 保持清零状态即可
            }
        }
    }
}
