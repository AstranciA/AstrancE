use core::fmt;

use num_enum::TryFromPrimitive;

use crate::arch::syscall::SyscallId;

mod fs;
mod process;

pub fn syscall(syscall_id: usize, args: [usize; 3]) -> isize {
    match SyscallId::try_from(syscall_id).expect("invalid syscall") {
        SyscallId::SyscallWrite => fs::sys_write(args[0], args[1] as *const u8, args[2]),
        SyscallId::SyscallExit => process::sys_exit(args[0] as i32),
        SyscallId::SyscallYield => process::sys_yield(),
        SyscallId::SyscallGetTime => process::sys_get_time() as isize,
        //_ => panic!("unsupported syscall id: {}", syscall_id as usize),
    }
}
