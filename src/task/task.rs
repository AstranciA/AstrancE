use crate::timer::get_time_ms;

use super::{info::TaskInfo, TaskContext};

#[derive(Copy, Clone)]
pub struct TaskControlBlock {
    pub task_status: TaskStatus,
    pub task_cx: TaskContext,
    pub task_info: Option<TaskInfo>,
    pub last_run_time: usize,
    pub last_suspend_time: usize,
}

impl TaskControlBlock {
    pub fn resume(&mut self) {
        self.task_status = TaskStatus::Running;
        if self.task_info.unwrap().start_time == 0 {
            self.task_info.unwrap().start_time = get_time_ms();
        }
        self.last_run_time = get_time_ms();
    }

    pub fn suspend(&mut self) {
        self.last_suspend_time = get_time_ms();
        self.task_info
            .as_mut()
            .unwrap()
            .add_cpu_time(self.last_suspend_time - self.last_run_time);
        self.task_status = TaskStatus::Ready;
    }

    pub fn exit(&mut self) {
        let task_info = self.task_info.as_mut().unwrap();
        task_info.end_time = get_time_ms();
        self.task_status = TaskStatus::Exited;
        info!(
            "Task {} exited: start_time: {}, end_time: {}, cpu_time: {}",
            task_info.id, task_info.start_time, task_info.end_time, task_info.cpu_time
        );
    }
}

#[derive(Clone, Copy, PartialEq)]
pub enum TaskStatus {
    UnInit,
    Ready,
    Running,
    Exited,
 }
