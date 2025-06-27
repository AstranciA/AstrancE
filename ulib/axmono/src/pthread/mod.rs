use core::{ptr, time::Duration};

use alloc::{collections::btree_map::BTreeMap, sync::Arc};
use axerrno::{LinuxError, LinuxResult};
use axhal::mem::phys_to_virt;
use axmm::{FrameTracker, FrameTrackerRef, TrackedPhysAddr};
use axtask::{TaskExtRef, WaitQueue, current};
use bitflags::bitflags;
use linux_raw_sys::general::*;
use memory_addr::{MemoryAddr, VirtAddr};
use numeric_enum_macro::numeric_enum;
use spin::RwLock;

numeric_enum! {
    #[repr(u8)] // 基本操作码通常只占用低位，u8 足够
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    pub enum FutexOp {
        Wait = FUTEX_WAIT as u8,
        Wake = FUTEX_WAKE as u8,
        Fd = FUTEX_FD as u8,
        Requeue = FUTEX_REQUEUE as u8,
        CmpRequeue = FUTEX_CMP_REQUEUE as u8,
        WakeOp = FUTEX_WAKE_OP as u8,
        LockPi = FUTEX_LOCK_PI as u8,
        UnlockPi = FUTEX_UNLOCK_PI as u8,
        TryLockPi = FUTEX_TRYLOCK_PI as u8,
        WaitBitset = FUTEX_WAIT_BITSET as u8,
        WakeBitset = FUTEX_WAKE_BITSET as u8,
        WaitRequeuePi = FUTEX_WAIT_REQUEUE_PI as u8,
        CmpRequeuePi = FUTEX_CMP_REQUEUE_PI as u8,
        LockPi2 = FUTEX_LOCK_PI2 as u8,
    }
}

impl TryFrom<usize> for FutexOp {
    type Error = LinuxError;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        Self::try_from((value as u32 & FUTEX_CMD_MASK as u32) as u8).map_err(|_| LinuxError::EINVAL)
    }
}

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct FutexFlags: usize {
        const PRIVATE = FUTEX_PRIVATE_FLAG as usize; // FUTEX_PRIVATE_FLAG
        const CLOCK_REALTIME = FUTEX_CLOCK_REALTIME as usize; // FUTEX_CLOCK_REALTIME
        // TODO: 其他 futex 标志位
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FutexAddr {
    Phys(TrackedPhysAddr),
    Virt(VirtAddr),
}

// 实现 Ord 和 PartialOrd 需要更复杂的逻辑，因为 Phys 和 Virt 之间没有自然的顺序
// 通常的做法是，先比较变体类型，再比较内部值。
// 但对于 BTreeMap 来说，只要提供一个稳定的排序即可，不一定需要有实际意义的顺序。
impl PartialOrd for FutexAddr {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for FutexAddr {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        match (self, other) {
            (FutexAddr::Phys(p1), FutexAddr::Phys(p2)) => p1.as_phys_addr().cmp(&p2.as_phys_addr()),
            (FutexAddr::Virt(v1), FutexAddr::Virt(v2)) => v1.cmp(v2),
            // 定义 Phys 和 Virt 之间的顺序，例如 Phys 总是小于 Virt
            (FutexAddr::Phys(_), FutexAddr::Virt(_)) => core::cmp::Ordering::Less,
            (FutexAddr::Virt(_), FutexAddr::Phys(_)) => core::cmp::Ordering::Greater,
        }
    }
}

impl Into<VirtAddr> for FutexAddr {
    fn into(self) -> VirtAddr {
        match self {
            Self::Phys(pa) => phys_to_virt(pa.as_phys_addr()),
            Self::Virt(va) => va,
        }
    }
}

pub static FUTEX_WQ: RwLock<BTreeMap<FutexAddr, Arc<WaitQueue>>> = RwLock::new(BTreeMap::new());

/// futex 系统调用的底层实现
///
/// # Arguments
/// * `vaddr` - 用户空间的 futex 变量虚拟地址。
/// * `op` - futex 操作码 (Wait, Wake 等)。
/// * `val` - 操作相关的值。
/// * `timeout_ns` - 等待超时时间（纳秒），None 表示无限期等待。
///
/// # Returns
/// `Ok(())` 表示成功，`Err(isize)` 表示错误码。
pub fn futex(
    vaddr: VirtAddr,
    op: FutexOp,
    val: u32,
    flags: FutexFlags,
    timeout: Option<Duration>,
) -> LinuxResult {
    // 假设你的内核有能力将用户虚拟地址转换为物理地址和 FrameTracker
    // 这是处理 FutexAddr::Phys 的关键步骤
    // TODO: 实现 vaddr 到 (FrameTracker, u32) 的转换
    // 这需要访问当前进程的页表，并检查页属性（例如是否是共享内存）
    // 如果无法转换为物理地址（例如不是共享内存），则默认为 VirtAddr
    let futex_addr_key = {
        // 这是一个占位符，你需要根据你的 MMU 和页表管理实现这个逻辑
        // 伪代码：
        // if is_shared_memory(vaddr) {
        //     let (frame_tracker, offset) = translate_vaddr_to_phys_frame(vaddr);
        //     FutexAddr::Phys((frame_tracker, offset))
        // } else {
        //     FutexAddr::Virt(vaddr)
        // }

        // 暂时为了编译通过，我们假设所有 futex 都是进程私有的，使用 VirtAddr
        // 但实际实现中，你需要根据 op 中的标志位（FUTEX_PRIVATE/SHARED）和页表来决定
        FutexAddr::Virt(vaddr)
    };
    warn!("futex <= {futex_addr_key:?} {op:?} {flags:?}");
    // 将 timeout_ns 转换为 Duration
    match op {
        FutexOp::Wait => {
            // 1. 读取用户空间地址的当前值
            // 直接写入用户地址，不用安全检查。
            let current_val = unsafe { ptr::read_volatile(vaddr.as_ptr() as *const u32) };
            // 2. 检查当前值是否与期望值匹配
            // 如果不匹配，表示条件已经不满足，立即返回，不睡眠
            warn!("wait: curr_val: {current_val}, val: {val}");
            if current_val != val {
                return Err(LinuxError::EAGAIN);
            }
            // 3. 获取或创建与 futex_addr_key 关联的 WaitQueue
            let wait_queue_instance = {
                let mut queues = FUTEX_WQ.write(); // Wait 操作需要写锁，因为可能插入新的 WaitQueue
                // 使用 entry().or_insert_with() 来获取或创建 WaitQueue
                queues
                    .entry(futex_addr_key)
                    .or_insert_with(|| Arc::new(WaitQueue::new()))
                    .clone()
            }; // 写锁在这里自动释放
            // 4. 让当前线程在该 WaitQueue 上等待
            // condition 闭包在等待前和每次被唤醒后都会被检查
            if let Some(timeout_duration) = timeout {
                wait_queue_instance.wait_timeout(timeout_duration);
            } else {
                wait_queue_instance.wait();
            }
            warn!("task wake!");

            Ok(())
        }
        FutexOp::Wake => {
            let mut woken_count = 0;
            {
                let queues = FUTEX_WQ.read(); // Wake 操作只需要读锁
                if let Some(wait_queue_instance) = queues.get(&futex_addr_key) {
                    // 唤醒指定数量的线程 (val)
                    // 如果 val 为 0，表示唤醒所有
                    if val == 0 {
                        wait_queue_instance.notify_all(false);
                    } else {
                        wait_queue_instance.notify_n(val as usize, false);
                    }
                    // 注意：这里我们不立即移除队列，因为可能还有其他操作会用到它
                    // 只有当所有等待者都离开，且没有新的等待者加入时，才考虑清理
                }
            } // 读锁在这里自动释放
            // 唤醒操作完成后，可能需要立即进行一次调度，让被唤醒的线程有机会运行
            // 假设你的调度器有这样的功能
            // Scheduler::yield_cpu(); // 如果你的调度器需要显式 yield
            Ok(())
        }
        // ... 其他 FutexOp 的处理
        _ => {
            Err(LinuxError::EINVAL) // EINVAL (Invalid argument)
        }
    }
}
