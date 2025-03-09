use riscv::register::satp::Satp;

use crate::{
    mm::{
        address::{PhysPageNum, VirtAddr},
        memory_set::{MapPermission, MemorySet, KERNEL_SPACE},
    },
    timer::get_time_ms,
    trap::{context::TrapContext, trap_handler},
};

use super::{info::TaskInfo, kernel_stack_position, TaskContext, TRAP_CONTEXT};

pub struct TaskControlBlock {
    pub task_status: TaskStatus,
    pub task_cx: TaskContext,
    pub memory_set: MemorySet,
    pub trap_cx_ppn: PhysPageNum,
    pub base_size: usize,
    pub task_info: Option<TaskInfo>,
    pub last_run_time: usize,
    pub last_suspend_time: usize,
}

impl TaskControlBlock {
    pub fn new(elf_data: &[u8], app_id: usize) -> Self {
        let (memory_set, user_sp, entry_point) = MemorySet::from_elf(elf_data);
        let trap_cx_ppn = memory_set
            .page_table
            .translate(VirtAddr::from(TRAP_CONTEXT).into())
            .unwrap()
            .ppn();
        println!("trap_cx_ppn: {:#x}", trap_cx_ppn.0);
        let task_status = TaskStatus::Ready;
        let (kernel_stack_bottom, kernel_stack_top) = kernel_stack_position(app_id);

        KERNEL_SPACE.exclusive_access().insert_framed_area(
            kernel_stack_bottom.into(),
            kernel_stack_top.into(),
            MapPermission::R | MapPermission::W,
        );

        let task_control_block = Self {
            task_status,
            task_cx: TaskContext::prepare_restore(kernel_stack_top as *const usize),
            memory_set,
            trap_cx_ppn,
            base_size: user_sp,
            last_run_time: 0,
            task_info: Some(TaskInfo::new(app_id)),
            last_suspend_time: 0,
        };

        let trap_cx = task_control_block.get_trap_cx();
        *trap_cx = TrapContext::app_init_context(
            entry_point,
            user_sp,
            KERNEL_SPACE.exclusive_access().token(),
            kernel_stack_top,
            trap_handler as usize,
        );

        task_control_block
    }

    pub fn get_trap_cx(&self) -> &'static mut TrapContext {
        self.trap_cx_ppn.get_mut()
    }

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

    pub fn get_user_token(&self) -> Satp {
        self.memory_set.token()
    }
}

#[derive(Clone, Copy, PartialEq)]
pub enum TaskStatus {
    UnInit,
    Ready,
    Running,
    Exited,
}
