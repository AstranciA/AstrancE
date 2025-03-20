use arceos_posix_api::{self as api, ctypes};
use core::ffi::c_char;
use core::ffi::c_int;

pub fn ax_openat(dirfd: c_int,
                  filename: *const c_char,
                  flags: c_int,
                  mode: ctypes::mode_t,
) -> isize{
    //检查位置安全性
    api::sys_openat(dirfd,filename,flags,mode) as isize
}

pub fn ax_lseek(fd: c_int, offset: ctypes::off_t, whence: c_int) -> isize {
    // 原闭包内的具体逻辑
    let res = (|| -> axerrno::LinuxResult<_> {
        use axerrno::LinuxError;
        use axvfs::SeekFrom;

        let pos = match whence as u32 {
            x if x == SeekFrom::CUR as u32 => SeekFrom::Current(offset),
            x if x == SeekFrom::SET as u32 => SeekFrom::Start(offset as u64),
            x if x == SeekFrom::END as u32 => SeekFrom::End(offset),
            _ => return Err(LinuxError::EINVAL),
        };
        let file = current_process().get_file(fd as fd_num)?;
        let off = file.lseek(pos)?;
        Ok(off)
    })();
    
    match res {
        Ok(_) | Err(axerrno::LinuxError::EAGAIN) => debug!("lseek => {:?}", res),
        Err(_) => info!("lseek => {:?}", res),
    }
    
    match res {
        Ok(v) => v as isize,
        Err(e) => -e.code() as isize,
    }
}