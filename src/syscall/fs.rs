use crate::{
    mm::page_table::PageTable,
    task::{current_user_token, TASK_MANAGER},
};

const FD_STDOUT: usize = 1;

pub fn sys_write(fd: usize, buf: *const u8, len: usize) -> isize {
    match fd {
        FD_STDOUT => {
            let buffers = PageTable::translated_byte_buffer(current_user_token(), buf, len);
            for buffer in buffers {
                print!("{}", str::from_utf8(buffer).unwrap());
            }
            len as isize
        }
        _ => {
            panic!("Unsupported file descriptor in sys_write: {}", fd)
        }
    }
}
