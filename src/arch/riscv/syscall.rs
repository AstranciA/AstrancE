use core::fmt;

use num_enum::TryFromPrimitive;

#[derive(TryFromPrimitive)]
#[num_enum(error_type(name = UnsupportSyscallError, constructor = UnsupportSyscallError::new))]
#[repr(usize)]
pub enum SyscallId {
    SyscallWrite = 64,
    SyscallExit = 93,
    SyscallYield = 124,
    SyscallGetTime = 169,
}

pub struct UnsupportSyscallError {
    syscall_id: usize,
}

impl UnsupportSyscallError {
    fn new(syscall_id: usize) -> Self {
        Self { syscall_id }
    }
}
impl fmt::Debug for UnsupportSyscallError {
    fn fmt(&self, stream: &'_ mut fmt::Formatter<'_>) -> fmt::Result {
        write!(stream, "unsupported syscall id: {}", self.syscall_id)
    }
}
impl fmt::Display for UnsupportSyscallError {
    fn fmt(&self, stream: &'_ mut fmt::Formatter<'_>) -> fmt::Result {
        write!(stream, "unsupported syscall id: {}", self.syscall_id)
    }
}
