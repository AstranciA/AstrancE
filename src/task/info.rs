#[derive(Clone, Copy)]
pub struct TaskInfo {
    pub id: usize,
    pub start_time: usize,
    pub end_time: usize,
    pub cpu_time: usize,
}

impl TaskInfo {
    pub fn new(id: usize) -> Self {
        Self {
            id,
            start_time: 0,
            end_time: 0,
            cpu_time: 0,
        }
    }

    pub fn add_cpu_time(&mut self, time: usize) {
        self.cpu_time += time;
    }

    pub fn print(&self) {
        kprintln!(
            "TaskInfo: id: {}",
            self.id,
        );
    }
}
