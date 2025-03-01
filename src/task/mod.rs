mod context;
mod switch;

mod info;
#[allow(clippy::module_inception)]
mod task;

use core::ops::Add;

pub use context::TaskContext;
use info::TaskInfo;
use lazy_static::lazy_static;
use switch::__switch;
use task::{TaskControlBlock, TaskStatus};

use crate::{
    config::*,
    loader::{get_base_i, get_num_app, init_app_cx},
    sbi::shutdown,
    sync::UPSafeCell,
    timer::{get_time, get_time_ms},
};

pub struct TaskManager {
    pub num_app: usize,
    pub inner: UPSafeCell<TaskManagerInner>,
}

pub struct TaskManagerInner {
    pub tasks: [TaskControlBlock; MAX_APP_NUM],
    pub start_time: usize,
    pub end_time: usize,
    current_task: usize,
}

lazy_static! {
    pub static ref TASK_MANAGER: TaskManager = {
        let num_app = get_num_app();
        let mut tasks = [TaskControlBlock {
            task_cx: TaskContext::zero_init(),
            task_status: TaskStatus::UnInit,
            task_info: None,
            last_run_time: 0,
            last_suspend_time: 0,
        }; MAX_APP_NUM];

        for (i, task) in tasks.iter_mut().enumerate() {
            task.task_cx = TaskContext::prepare_restore(init_app_cx(i) as *const usize);
            task.task_status = TaskStatus::Ready;
            task.task_info = Some(TaskInfo::new(
                i,
                get_base_i(i),
                get_base_i(i) + APP_SIZE_LIMIT,
            ));
        }
        TaskManager {
            num_app,
            inner: UPSafeCell::new(TaskManagerInner {
                tasks,
                current_task: 0,
                start_time: 0,
                end_time: 0,
            }),
        }
    };
}

impl TaskManager {
    fn run_first_task(&self) -> ! {
        let mut inner = self.inner.exclusive_access();
        inner.start_time = get_time_ms();
        let task0 = &mut inner.tasks[0];
        task0.resume();
        let next_task_ptr = &task0.task_cx as *const TaskContext;
        drop(inner);

        let mut _unused = TaskContext::zero_init();

        unsafe {
            __switch(&mut _unused as *mut TaskContext, next_task_ptr);
        }
        panic!("unreachable in run_first_task!");
    }

    fn mark_current_suspended(&self) {
        let mut inner = self.inner.exclusive_access();
        let current = inner.current_task;
        inner.tasks[current].suspend();
    }

    fn mark_current_exited(&self) {
        let mut inner = self.inner.exclusive_access();
        let current = inner.current_task;
        inner.tasks[current].exit();
    }

    fn find_next_task(&self) -> Option<usize> {
        let inner = self.inner.exclusive_access();
        let current = inner.current_task;
        (current + 1..current + 1 + self.num_app)
            .map(|id| id % self.num_app)
            .find(|id| inner.tasks[*id].task_status == TaskStatus::Ready)
    }

    fn run_next_task(&self) {
        if let Some(next) = self.find_next_task() {
            let mut inner = self.inner.exclusive_access();
            let current = inner.current_task;
            inner.tasks[next].resume();
            inner.current_task = next;

            let current_task_cx_ptr = &mut inner.tasks[current].task_cx as *mut TaskContext;
            let next_task_cx_ptr = &inner.tasks[next].task_cx as *const TaskContext;

            drop(inner);

            if current != next {
                kprintln!("Switch from task {} to {}", current, next);
            }

            unsafe {
                __switch(current_task_cx_ptr, next_task_cx_ptr);
            }
        } else {
            let mut inner = self.inner.exclusive_access();
            inner.end_time = get_time();
            let task_cpu_time: usize = inner
                .tasks
                .as_ref()
                .iter()
                .map(|task| task.task_info.unwrap().cpu_time)
                .sum();
            info!("Task CPU time: {} ms", task_cpu_time);
            info!(
                "Effeciency: {:.2} %",
                task_cpu_time *100 / (inner.end_time - inner.start_time) 
            );

            kprintln!("All applications completed!");
            shutdown(false);
        }
    }

    pub fn get_current_task_id(&self) -> usize {
        self.inner.access().current_task
    }

    pub fn get_task_info(&self, id: usize) -> Option<TaskInfo> {
        self.inner.exclusive_access().tasks[id].task_info
    }

    pub fn print_tasks_info(&self) {
        for i in 0..self.num_app {
            self.get_task_info(i).unwrap().print();
        }
    }

    pub fn analyze_time(&self) {}
}

/// run first task
pub fn run_first_task() {
    TASK_MANAGER.run_first_task();
}

/// rust next task
fn run_next_task() {
    TASK_MANAGER.run_next_task();
}

/// suspend current task
fn mark_current_suspended() {
    TASK_MANAGER.mark_current_suspended();
}

/// exit current task
fn mark_current_exited() {
    TASK_MANAGER.mark_current_exited();
}

/// suspend current task, then run next task
pub fn suspend_current_and_run_next() {
    mark_current_suspended();
    run_next_task();
}

/// exit current task,  then run next task
pub fn exit_current_and_run_next() {
    mark_current_exited();
    run_next_task();
}
pub fn print_tasks_info() {
    TASK_MANAGER.print_tasks_info();
}
