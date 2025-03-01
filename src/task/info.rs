use crate::loader::{UserStack, USER_STACK};

#[derive(Clone, Copy)]
pub struct TaskInfo {
    pub id: usize,
    start_addr: usize,
    end_addr: usize,
    stack: &'static UserStack,
    app_slice: &'static [u8],
    pub start_time: usize,
    pub end_time: usize,
    pub cpu_time: usize,
}

impl TaskInfo {
    pub fn new(id: usize, start_addr: usize, end_addr: usize) -> Self {
        let app_slice =
            unsafe { core::slice::from_raw_parts(start_addr as *const u8, end_addr - start_addr) };

        Self {
            id,
            start_addr,
            end_addr,
            app_slice,
            stack: &USER_STACK[id],
            start_time: 0,
            end_time: 0,
            cpu_time: 0,
        }
    }

    pub fn is_valid_addr(&self, addr: *const u8, len: usize) -> bool {
        let program_range = self.app_slice.as_ptr_range();
        let stack_range = self.stack.data.as_ptr_range();
        let end = addr.wrapping_add(len);
        (program_range.contains(&addr) && program_range.contains(&end))
            || (stack_range.contains(&(addr)) && stack_range.contains(&(end)))
    }

    pub fn add_cpu_time(&mut self, time: usize) {
        self.cpu_time += time;
    }

    pub fn print(&self) {
        kprintln!(
            "TaskInfo: id: {}, app_addr: {:#x}..{:#x}, stack: {:#x}",
            self.id,
            self.start_addr,
            self.end_addr,
            self.stack.data.as_ptr() as usize,
        );
    }
}
