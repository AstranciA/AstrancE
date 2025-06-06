use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;
use crate::wait_queue::WaitQueue;
use crate::{AxTaskRef, TaskState, current};
use log::{debug, warn};
use axerrno::LinuxError; // 引入 LinuxError 枚举

// 全局的 futex 等待队列映射，键是 futex 地址，值是对应的等待队列
static FUTEX_QUEUES: Mutex<BTreeMap<usize, Arc<WaitQueue>>> = Mutex::new(BTreeMap::new());

// 用于生成唯一等待队列ID的计数器（用于调试）
static QUEUE_ID_COUNTER: AtomicU64 = AtomicU64::new(0);

/// 获取或创建与指定地址关联的等待队列
fn get_or_create_queue(uaddr: usize) -> Arc<WaitQueue> {
    let mut queues = FUTEX_QUEUES.lock();
    queues.entry(uaddr)
        .or_insert_with(|| {
            let id = QUEUE_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
            let wq = Arc::new(WaitQueue::new());
            debug!("Created new WaitQueue (ID: {}) for futex address {:#x}", id, uaddr);
            wq
        })
        .clone()
}

/// 使当前线程在指定地址上等待，直到被唤醒或值不匹配
/// uaddr: 等待的地址
/// expected: 期望的值，如果地址上的值不等于此值，则不等待
/// timeout: 超时时间（当前未完全实现）
/// 返回值：成功返回 Ok(()), 失败返回 Err(error)
pub fn futex_wait(uaddr: *mut i32, expected: i32, timeout: *const ()) -> Result<(), LinuxError> {
    // 安全性检查：确保地址非空且在用户态地址空间（具体范围需根据系统定义）
    if uaddr.is_null() {
        return Err(LinuxError::EINVAL); // 无效参数
    }

    // 检查地址上的值是否与 expected 一致
    let current_val = unsafe { *uaddr };
    if current_val != expected {
        debug!("Futex wait failed: value mismatch at {:#x}, expected {}, got {}", uaddr as usize, expected, current_val);
        return Err(LinuxError::EAGAIN); // 资源暂时不可用（值不匹配）
    }

    // 获取或创建与该地址关联的等待队列
    let uaddr_usize = uaddr as usize;
    let wq = get_or_create_queue(uaddr_usize);

    // 获取当前任务并标记其在等待队列中
    let curr = current();
    curr.set_in_wait_queue(true);
    debug!("Task {} waiting on futex address {:#x}", curr.id_name(), uaddr_usize);

    // 阻塞当前任务，加入等待队列
    wq.wait();

    // 被唤醒后返回成功
    debug!("Task {} woken up from futex address {:#x}", curr.id_name(), uaddr_usize);
    curr.set_in_wait_queue(false);
    Ok(())
}

/// 唤醒在指定地址上等待的线程
/// uaddr: 等待的地址
/// count: 最多唤醒的线程数量
/// 返回值：实际唤醒的线程数量
pub fn futex_wake(uaddr: *mut i32, count: usize) -> usize {
    // 安全性检查：确保地址非空
    if uaddr.is_null() {
        return 0;
    }

    let uaddr_usize = uaddr as usize;
    let mut queues = FUTEX_QUEUES.lock();

    if let Some(wq) = queues.get(&uaddr_usize) {
        debug!("Waking up to {} tasks on futex address {:#x}", count, uaddr_usize);
        let mut woken = 0;
        for _ in 0..count {
            if !wq.notify_one(true) {
                break; // 队列中没有更多任务
            }
            woken += 1;
        }
        if wq.is_empty() {
            queues.remove(&uaddr_usize); // 如果队列为空，移除以节省内存
            debug!("Removed empty WaitQueue for futex address {:#x}", uaddr_usize);
        }
        debug!("Woke up {} tasks on futex address {:#x}", woken, uaddr_usize);
        woken
    } else {
        debug!("No tasks waiting on futex address {:#x}", uaddr_usize);
        0
    }
}
