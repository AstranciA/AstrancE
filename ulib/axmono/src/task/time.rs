//! **代码来源声明：**
//! 本文件代码来自
//! [oscomp/starry-next](https://github.com/oscomp/starry-next) 项目。
//!
use axhal::time::{NANOS_PER_MICROS, NANOS_PER_SEC};
use axlog::debug;
use axsignal::Signal;
use linux_raw_sys::general::{itimerval, timeval};

numeric_enum_macro::numeric_enum! {
    #[repr(i32)]
    #[allow(non_camel_case_types)]
    #[derive(Eq, PartialEq, Debug, Clone, Copy)]
    pub enum TimerType {
    /// 表示目前没有任何计时器(不在linux规范中，是os自己规定的)
    NONE = -1,
    /// 统计系统实际运行时间
    REAL = 0,
    /// 统计用户态运行时间
    VIRTUAL = 1,
    /// 统计进程的所有用户态/内核态运行时间
    PROF = 2,
    }
}

impl From<usize> for TimerType {
    fn from(num: usize) -> Self {
        match Self::try_from(num as i32) {
            Ok(val) => val,
            Err(_) => Self::NONE,
        }
    }
}

/// 定时器配置结构，对应 POSIX itimerval
#[derive(Debug, Clone, Copy)]
pub struct ItimerConfig {
    pub interval_sec: u64,
    pub interval_usec: u64,
    pub value_sec: u64,
    pub value_usec: u64,
}

impl From<itimerval> for ItimerConfig {
    fn from(value: itimerval) -> Self {
        Self {
            interval_sec: value.it_interval.tv_sec as _,
            interval_usec: value.it_interval.tv_usec as _,
            value_sec: value.it_value.tv_sec as _,
            value_usec: value.it_value.tv_usec as _,
        }
    }
}
impl From<ItimerConfig> for itimerval {
    fn from(value: ItimerConfig) -> Self {
        Self {
            it_interval: timeval {
                tv_sec: value.interval_sec as _,
                tv_usec: value.interval_usec as _,
            },
            it_value: timeval {
                tv_sec: value.value_sec as _,
                tv_usec: value.value_usec as _,
            },
        }
    }
}

impl Default for ItimerConfig {
    fn default() -> Self {
        Self {
            interval_sec: 0,
            interval_usec: 0,
            value_sec: 0,
            value_usec: 0,
        }
    }
}

impl ItimerConfig {
    /// 将秒和微秒转换为纳秒
    pub fn to_nanos(&self) -> (u64, u64) {
        let interval_ns = self.interval_sec * NANOS_PER_SEC + self.interval_usec * NANOS_PER_MICROS;
        let value_ns = self.value_sec * NANOS_PER_SEC + self.value_usec * NANOS_PER_MICROS;
        (interval_ns, value_ns)
    }

    /// 从纳秒转换为秒和微秒
    pub fn from_nanos(interval_ns: u64, value_ns: u64) -> Self {
        Self {
            interval_sec: interval_ns / NANOS_PER_SEC,
            interval_usec: (interval_ns % NANOS_PER_SEC) / NANOS_PER_MICROS,
            value_sec: value_ns / NANOS_PER_SEC,
            value_usec: (value_ns % NANOS_PER_SEC) / NANOS_PER_MICROS,
        }
    }

    /// 检查定时器是否有效（至少有一个时间值大于0）
    pub fn is_valid(&self) -> bool {
        self.interval_sec > 0 || self.interval_usec > 0 || self.value_sec > 0 || self.value_usec > 0
    }
}

pub struct TimeStat {
    utime_ns: usize,
    stime_ns: usize,
    user_timestamp: usize,
    kernel_timestamp: usize,
    timer_type: TimerType,
    timer_interval_ns: usize,
    timer_remained_ns: usize,
    // 新增：支持 POSIX itimerval 定时器
    itimer_real: ItimerConfig,
    itimer_virtual: ItimerConfig,
    itimer_prof: ItimerConfig,
    // 当前活跃的定时器类型
    active_itimer: Option<TimerType>,
}

impl Default for TimeStat {
    fn default() -> Self {
        Self::new()
    }
}

impl TimeStat {
    pub fn new() -> Self {
        Self {
            utime_ns: 0,
            stime_ns: 0,
            user_timestamp: 0,
            kernel_timestamp: 0,
            timer_type: TimerType::NONE,
            timer_interval_ns: 0,
            timer_remained_ns: 0,
            itimer_real: ItimerConfig::default(),
            itimer_virtual: ItimerConfig::default(),
            itimer_prof: ItimerConfig::default(),
            active_itimer: None,
        }
    }

    pub fn output(&self) -> (usize, usize) {
        (self.utime_ns, self.stime_ns)
    }

    pub fn reset(&mut self, current_timestamp: usize) {
        self.utime_ns = 0;
        self.stime_ns = 0;
        self.user_timestamp = 0;
        self.kernel_timestamp = current_timestamp;
    }

    pub fn switch_into_kernel_mode(&mut self, current_timestamp: usize) {
        let now_time_ns = current_timestamp;
        let delta = now_time_ns - self.kernel_timestamp;
        self.utime_ns += delta;
        self.kernel_timestamp = now_time_ns;
        if self.timer_type != TimerType::NONE {
            self.update_timer(delta);
        };
        // 更新 POSIX 定时器
        self.update_itimer(delta);
    }

    pub fn switch_into_user_mode(&mut self, current_timestamp: usize) {
        let now_time_ns = current_timestamp;
        let delta = now_time_ns - self.kernel_timestamp;
        self.stime_ns += delta;
        self.user_timestamp = now_time_ns;
        if self.timer_type == TimerType::REAL || self.timer_type == TimerType::PROF {
            self.update_timer(delta);
        }
        // 更新 POSIX 定时器
        self.update_itimer(delta);
    }

    pub fn switch_from_old_task(&mut self, current_timestamp: usize) {
        let now_time_ns = current_timestamp;
        let delta = now_time_ns - self.kernel_timestamp;
        self.stime_ns += delta;
        self.kernel_timestamp = now_time_ns;
        if self.timer_type == TimerType::REAL || self.timer_type == TimerType::PROF {
            self.update_timer(delta);
        }
        // 更新 POSIX 定时器
        self.update_itimer(delta);
    }

    pub fn switch_to_new_task(&mut self, current_timestamp: usize) {
        let now_time_ns = current_timestamp;
        let delta = now_time_ns - self.kernel_timestamp;
        self.kernel_timestamp = now_time_ns;
        if self.timer_type == TimerType::REAL {
            self.update_timer(delta);
        }
        // 更新 POSIX 定时器
        self.update_itimer(delta);
    }

    pub fn set_timer(
        &mut self,
        timer_interval_ns: usize,
        timer_remained_ns: usize,
        timer_type: usize,
    ) -> bool {
        self.timer_type = timer_type.into();
        self.timer_interval_ns = timer_interval_ns;
        self.timer_remained_ns = timer_remained_ns;
        self.timer_type != TimerType::NONE
    }

    pub fn update_timer(&mut self, delta: usize) {
        if self.timer_remained_ns == 0 {
            return;
        }
        if self.timer_remained_ns > delta {
            self.timer_remained_ns -= delta;
        }
    }

    /// 设置 POSIX 定时器
    pub fn set_itimer(&mut self, timer_type: TimerType, config: ItimerConfig) -> ItimerConfig {
        let old_config = match timer_type {
            TimerType::REAL => self.itimer_real,
            TimerType::VIRTUAL => self.itimer_virtual,
            TimerType::PROF => self.itimer_prof,
            TimerType::NONE => return ItimerConfig::default(),
        };

        match timer_type {
            TimerType::REAL => {
                self.itimer_real = config;
                if config.is_valid() {
                    self.active_itimer = Some(TimerType::REAL);
                }
            }
            TimerType::VIRTUAL => {
                self.itimer_virtual = config;
                if config.is_valid() {
                    self.active_itimer = Some(TimerType::VIRTUAL);
                }
            }
            TimerType::PROF => {
                self.itimer_prof = config;
                if config.is_valid() {
                    self.active_itimer = Some(TimerType::PROF);
                }
            }
            TimerType::NONE => {}
        }

        old_config
    }

    /// 获取 POSIX 定时器配置
    pub fn get_itimer(&self, timer_type: TimerType) -> ItimerConfig {
        match timer_type {
            TimerType::REAL => self.itimer_real,
            TimerType::VIRTUAL => self.itimer_virtual,
            TimerType::PROF => self.itimer_prof,
            TimerType::NONE => ItimerConfig::default(),
        }
    }

    /// 更新 POSIX 定时器
    fn update_itimer(&mut self, delta: usize) {
        if let Some(active_type) = self.active_itimer {
            let config = self.get_itimer(active_type);
            let (interval_ns, value_ns) = config.to_nanos();

            if value_ns > 0 {
                let new_value_ns = if value_ns > delta as u64 {
                    value_ns - delta as u64
                } else {
                    0
                };

                // 更新剩余时间
                let mut new_config = config;
                new_config.value_sec = new_value_ns / NANOS_PER_SEC;
                new_config.value_usec = (new_value_ns % NANOS_PER_SEC) / NANOS_PER_MICROS;

                self.set_itimer(active_type, new_config);

                // 如果定时器到期，需要发送信号
                if new_value_ns == 0 {
                    self.handle_itimer_expiry(active_type);

                    // 如果有间隔时间，重新启动定时器
                    if interval_ns > 0 {
                        let restart_config = ItimerConfig {
                            value_sec: interval_ns / NANOS_PER_SEC,
                            value_usec: (interval_ns % NANOS_PER_SEC) / NANOS_PER_MICROS,
                            ..config
                        };
                        self.set_itimer(active_type, restart_config);
                    } else {
                        // 没有间隔时间，清除活跃定时器
                        self.active_itimer = None;
                    }
                }
            }
        }
    }

    /// 处理定时器到期事件
    fn handle_itimer_expiry(&self, timer_type: TimerType) {
        let signal = match timer_type {
            TimerType::REAL => Signal::SIGALRM,
            TimerType::VIRTUAL => Signal::SIGVTALRM,
            TimerType::PROF => Signal::SIGPROF,
            TimerType::NONE => return,
        };

        // 记录定时器到期事件
        debug!(
            "Timer expired: {:?}, should send signal: {:?}",
            timer_type, signal
        );

        // 注意：实际的信号发送需要在外部处理，因为这里不能获取到进程的信号上下文
        // 我们将在系统调用层面处理信号发送
    }
}
