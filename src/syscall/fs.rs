use crate::task::{TaskManager, TASK_MANAGER};

const FD_STDOUT: usize = 1;

pub fn sys_write(fd: usize, buf: *const u8, len: usize) -> isize {
    match fd {
        FD_STDOUT => {
            let id = TASK_MANAGER.get_current_task_id();
            let task_info = TASK_MANAGER.get_task_info(id).unwrap();
            if !task_info.is_valid_addr(buf, len) {
                panic!(
                    "access invalid address in sys_write: [{:?}, {:?})",
                    buf,
                    buf.wrapping_add(len)
                );
            }
            let slice = unsafe { core::slice::from_raw_parts(buf, len) };
            let str = core::str::from_utf8(slice).unwrap();
            print!("{}", str);
            len as isize
        }
        _ => {
            panic!("Unsupported file descriptor in sys_write: {}", fd)
        }
    }
}
