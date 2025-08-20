//! POSIX 定时器管理模块
//!
//! 负责处理 setitimer/getitimer 系统调用和定时器信号发送

use alloc::vec::Vec;
use axerrno::LinuxResult;
use axhal::time::{NANOS_PER_MICROS, NANOS_PER_SEC, monotonic_time_nanos};
use axsignal::SigCode;
use axsignal::{Signal, siginfo::SigCodeCommon, siginfo::SigInfo};
use axsync::Mutex;
use axtask::{TaskExtRef, current};

use super::time::{ItimerConfig, TimerType};
use super::{PROCESS_TABLE, ProcessData};

/// 定时器管理器
pub struct ItimerManager {
    // 全局定时器列表，用于跟踪所有活跃的定时器
    active_timers: Vec<ActiveTimer>,
}

/// 活跃的定时器
struct ActiveTimer {
    pid: u32,
    timer_type: TimerType,
    config: ItimerConfig,
    start_time_ns: u64,
    next_expiry_ns: u64,
}

impl ItimerManager {
    pub const fn new() -> Self {
        Self {
            active_timers: Vec::new(),
        }
    }

    /// 设置定时器
    pub fn set_itimer(
        &mut self,
        pid: u32,
        timer_type: TimerType,
        config: ItimerConfig,
    ) -> LinuxResult<ItimerConfig> {
        // 查找并移除旧的定时器
        let old_config = self.remove_timer(pid, timer_type);

        // 如果新配置有效，添加到活跃定时器列表
        if config.is_valid() {
            let (_, value_ns) = config.to_nanos();
            let now_ns = monotonic_time_nanos();
            let next_expiry_ns = now_ns + value_ns;

            let timer = ActiveTimer {
                pid,
                timer_type,
                config,
                start_time_ns: now_ns,
                next_expiry_ns,
            };

            self.active_timers.push(timer);
        }

        Ok(old_config)
    }

    /// 获取定时器配置
    pub fn get_itimer(&self, pid: u32, timer_type: TimerType) -> ItimerConfig {
        for timer in &self.active_timers {
            if timer.pid == pid && timer.timer_type == timer_type {
                return timer.config;
            }
        }
        ItimerConfig::default()
    }

    /// 移除定时器
    fn remove_timer(&mut self, pid: u32, timer_type: TimerType) -> ItimerConfig {
        let mut old_config = ItimerConfig::default();
        let mut i = 0;

        while i < self.active_timers.len() {
            if self.active_timers[i].pid == pid && self.active_timers[i].timer_type == timer_type {
                old_config = self.active_timers[i].config;
                self.active_timers.remove(i);
                break;
            } else {
                i += 1;
            }
        }

        old_config
    }

    /// 检查并处理到期的定时器
    pub fn check_expired_timers(&mut self) {
        let now_ns = monotonic_time_nanos();
        let mut i = 0;

        while i < self.active_timers.len() {
            if self.active_timers[i].next_expiry_ns <= now_ns {
                let timer = self.active_timers.remove(i);
                self.handle_timer_expiry(&timer);

                // 检查是否需要重新启动定时器
                let (interval_ns, _) = timer.config.to_nanos();
                if interval_ns > 0 {
                    let restart_config = ItimerConfig {
                        value_sec: interval_ns / NANOS_PER_SEC,
                        value_usec: (interval_ns % NANOS_PER_SEC) / NANOS_PER_MICROS,
                        ..timer.config
                    };

                    let next_expiry_ns = now_ns + interval_ns;
                    let restart_timer = ActiveTimer {
                        pid: timer.pid,
                        timer_type: timer.timer_type,
                        config: restart_config,
                        start_time_ns: now_ns,
                        next_expiry_ns,
                    };

                    self.active_timers.push(restart_timer);
                }
            } else {
                i += 1;
            }
        }
    }

    /// 处理定时器到期事件
    fn handle_timer_expiry(&self, timer: &ActiveTimer) {
        let signal = match timer.timer_type {
            TimerType::REAL => Signal::SIGALRM,
            TimerType::VIRTUAL => Signal::SIGVTALRM,
            TimerType::PROF => Signal::SIGPROF,
            TimerType::NONE => return,
        };

        // 发送信号到对应的进程
        self.send_signal_to_process(timer.pid, signal);
    }

    /// 发送信号到进程
    fn send_signal_to_process(&self, pid: u32, signal: Signal) {
        if let Some(process) = PROCESS_TABLE.read().get(&pid) {
            if let Some(proc_data) = process.data::<ProcessData>() {
                let mut sigctx = proc_data.signal.lock();

                // 创建信号信息
                let siginfo =
                    SigInfo::new_simple(signal, SigCode::Common(SigCodeCommon::SI_KERNEL));

                // 发送信号
                sigctx.send_signal(signal, Some(siginfo));
            }
        }
    }
}

// 全局定时器管理器实例
static ITIMER_MANAGER: Mutex<ItimerManager> = Mutex::new(ItimerManager::new());

/// 设置定时器
pub fn set_itimer(
    which: i32,
    new_value: &ItimerConfig,
    old_value: Option<&mut ItimerConfig>,
) -> LinuxResult<()> {
    let timer_type = match which {
        0 => TimerType::REAL,    // ITIMER_REAL
        1 => TimerType::VIRTUAL, // ITIMER_VIRTUAL
        2 => TimerType::PROF,    // ITIMER_PROF
        _ => return Err(axerrno::LinuxError::EINVAL),
    };

    let curr = current();
    let pid = curr.task_ext().thread.process().pid() as u32;

    let mut manager = ITIMER_MANAGER.lock();
    let old_config = manager.set_itimer(pid, timer_type, *new_value)?;

    // 如果用户请求旧值，则填充
    if let Some(old_val) = old_value {
        *old_val = old_config;
    }

    Ok(())
}

/// 获取定时器配置
pub fn get_itimer(which: i32, curr_value: &mut ItimerConfig) -> LinuxResult<()> {
    let timer_type = match which {
        0 => TimerType::REAL,    // ITIMER_REAL
        1 => TimerType::VIRTUAL, // ITIMER_VIRTUAL
        2 => TimerType::PROF,    // ITIMER_PROF
        _ => return Err(axerrno::LinuxError::EINVAL),
    };

    let curr = current();
    let pid = curr.task_ext().thread.process().pid() as u32;

    let manager = ITIMER_MANAGER.lock();
    *curr_value = manager.get_itimer(pid, timer_type);

    Ok(())
}

/// 检查到期的定时器（应该在定时器中断或系统调用中调用）
pub fn check_expired_timers() {
    let mut manager = ITIMER_MANAGER.lock();
    manager.check_expired_timers();
}
