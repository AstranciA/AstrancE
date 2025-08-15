use crate::ctype_my::statx;
use crate::ctypes;
use crate::ctypes::{off_t, size_t, ssize_t};
use crate::imp::stdio::{stdin, stdout};
use crate::{
    utils::check_and_read_user_ptr, utils::copy_from_user, utils::copy_to_user,
    utils::write_back_user_ptr,
};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use axerrno::{LinuxError, LinuxResult, ax_err};
use axfs_vfs::{VfsNodeAttr, VfsNodeOps, VfsResult};
use axio::PollState;
use axio::SeekFrom;
use axns::{ResArc, def_resource};
use axtask::yield_now;
use core::ffi::{c_char, c_int, c_short, c_uint, c_void};
use core::time::Duration;
use flatten_objects::FlattenObjects;
use spin::Mutex;
use spin::{Once, RwLock};
pub const AX_FILE_LIMIT: usize = 1024;

static FILE_LIMIT: Mutex<(usize, usize)> = Mutex::new((AX_FILE_LIMIT, AX_FILE_LIMIT));

pub fn get_file_limit() -> usize {
    FILE_LIMIT.lock().0
}
pub fn get_file_limit_max() -> usize {
    FILE_LIMIT.lock().1
}

pub fn set_file_limit(new_cur: usize, new_max: usize) -> Result<(), LinuxError> {
    if new_cur > new_max || new_cur < 1 || new_max < 1 {
        return Err(LinuxError::EINVAL);
    }
    let current_count = current_fd_count();
    if current_count > new_cur {
        return Err(LinuxError::EBUSY);
    }
    let mut limit = FILE_LIMIT.lock();
    limit.0 = new_cur;
    limit.1 = new_max;
    Ok(())
}

#[allow(dead_code)]
pub trait FileLike: Send + Sync {
    fn read(&self, buf: &mut [u8]) -> LinuxResult<usize>;
    fn write(&self, buf: &[u8]) -> LinuxResult<usize>;
    fn stat(&self) -> LinuxResult<ctypes::stat>;
    fn statx(&self) -> LinuxResult<statx> {
        Err(LinuxError::EOPNOTSUPP)
    }
    fn read_at(&self, _buf: &mut [u8], _offset: u64) -> LinuxResult<usize> {
        warn!("read_at not implemented for this FileLike");
        Err(LinuxError::EINVAL)
    }
    fn write_at(&self, _buf: &[u8], _offset: u64) -> LinuxResult<usize> {
        warn!("write_at not implemented for this FileLike");
        Err(LinuxError::EINVAL)
    }
    fn truncate(&self, len: u64) -> LinuxResult<usize> {
        warn!("write_at not implemented for this FileLike");
        Err(LinuxError::EINVAL)
    }
    fn read_link(&self, buf: *mut c_char, bufsize: usize) -> LinuxResult<usize> {
        warn!("readlink not implemented for this FileLike");
        Err(LinuxError::EINVAL)
    }
    fn into_any(self: Arc<Self>) -> Arc<dyn core::any::Any + Send + Sync>;
    fn poll(&self) -> LinuxResult<PollState>;
    fn set_nonblocking(&self, nonblocking: bool) -> LinuxResult;

    fn fgetxattr(
        &self,
        name: *const c_char,
        buf: *mut c_void,
        buf_size: usize,
    ) -> LinuxResult<usize> {
        warn!("Unsupport fgetxattr for this type");
        Ok(0)
    }
    fn flistxattr(&self, list: *mut c_char, size: usize) -> LinuxResult<usize> {
        warn!("Unsupport fgetxattr for this type");
        Ok(0)
    }
    fn fsetxattr(
        &self,
        name: *const c_char,
        data: *mut c_void,
        data_size: usize,
        flags: usize,
    ) -> LinuxResult<usize> {
        warn!("Unsupport fsetxattr for this type");
        Ok(0)
    }
    fn fremovexattr(&self, name: *const c_char) -> LinuxResult<usize> {
        warn!("Unsupport fremovexattr for this type");
        Ok(0)
    }
    fn ioctl(
        &self,
        op: usize,
        arg1: usize,
        arg2: usize,
        arg3: usize,
        arg4: usize,
    ) -> LinuxResult<usize> {
        warn!("Unsupport ioctl for this type");
        Ok(0)
    }

    fn set_mtime(&self, mtime: u32, mtime_n: u32) -> LinuxResult<usize> {
        warn!("Unsupport set_mtime for this type");
        Ok(0)
    }
    fn set_atime(&self, atime: u32, atime_n: u32) -> LinuxResult<usize> {
        warn!("Unsupport set_atime for this type");
        Ok(0)
    }

    fn seek(&self, pos: SeekFrom) -> LinuxResult<u64> {
        warn!("Unsupport seek for this type");
        Ok(0)
    }

    fn is_pipe(&self) -> bool {
        warn!("Unsupport is_pipe for this type");
        false
    }
}

def_resource! {
    pub static FD_TABLE: ResArc<RwLock<FlattenObjects<Arc<dyn FileLike>, AX_FILE_LIMIT>>> = ResArc::new();
}

impl FD_TABLE {
    /// Return a copy of the inner table.
    pub fn copy_inner(&self) -> RwLock<FlattenObjects<Arc<dyn FileLike>, AX_FILE_LIMIT>> {
        let table = self.read();
        let mut new_table = FlattenObjects::new();
        for id in table.ids() {
            let _ = new_table.add_at(id, table.get(id).unwrap().clone());
        }
        RwLock::new(new_table)
    }

    pub fn clear(&self) {
        let mut table = self.write();
        let ids: Vec<_> = table.ids().collect();
        for i in ids {
            table.remove(i).unwrap();
        }
    }
}

/// Get the current number of open file descriptors
pub fn current_fd_count() -> usize {
    FD_TABLE.read().count()
}

/// Get a file by `fd`.
pub fn get_file_like(fd: c_int) -> LinuxResult<Arc<dyn FileLike>> {
    FD_TABLE
        .read()
        .get(fd as usize)
        .cloned()
        .ok_or(LinuxError::EBADF)
}

/// Add a file to the file descriptor table.
pub fn add_file_like(f: Arc<dyn FileLike>) -> LinuxResult<c_int> {
    if current_fd_count() >= get_file_limit() {
        return Err(LinuxError::EMFILE);
    }
    Ok(FD_TABLE.write().add(f).map_err(|_| LinuxError::EMFILE)? as c_int)
}

/// Close a file by `fd`.
pub fn close_file_like(fd: c_int) -> LinuxResult {
    let f = FD_TABLE
        .write()
        .remove(fd as usize)
        .ok_or(LinuxError::EBADF)?;
    drop(f);
    Ok(())
}

/// Close a file by `fd`.
pub fn sys_close(fd: c_int) -> c_int {
    debug!("sys_close <= {}", fd);
    // FIXME:
    /*
     *if (0..=2).contains(&fd) {
     *    return 0; // stdin, stdout, stderr
     *}
     */
    syscall_body!(sys_close, close_file_like(fd).map(|_| 0))
}

fn dup_fd(old_fd: c_int) -> LinuxResult<c_int> {
    let f = get_file_like(old_fd)?;
    let new_fd = add_file_like(f)?;
    Ok(new_fd)
}

/// Duplicate a file descriptor.
pub fn sys_dup(old_fd: c_int) -> c_int {
    debug!("sys_dup <= {}", old_fd);
    syscall_body!(sys_dup, dup_fd(old_fd))
}

/// Duplicate a file descriptor, but it uses the file descriptor number specified in `new_fd`.
pub fn sys_dup2(old_fd: c_int, new_fd: c_int) -> c_int {
    debug!("sys_dup2 <= old_fd: {}, new_fd: {}", old_fd, new_fd);
    syscall_body!(sys_dup2, {
        if old_fd == new_fd {
            let r = sys_fcntl(old_fd, ctypes::F_GETFD as _, 0);
            if r >= 0 {
                return Ok(old_fd);
            } else {
                return Ok(r);
            }
        }
        if new_fd as usize >= AX_FILE_LIMIT {
            return Err(LinuxError::EBADF);
        }

        let f = get_file_like(old_fd)?;
        let mut fd_table = FD_TABLE.write();
        // 先关闭 new_fd（如果存在）
        if fd_table.is_assigned(new_fd as usize) {
            debug!("Removing existing resource at new_fd={}", new_fd);
            fd_table.remove(new_fd as usize); // 移除旧资源
        }
        // 再绑定新资源
        fd_table.add_at(new_fd as usize, f).map_err(|e| {
            debug!("FD_TABLE.add_at failed for new_fd={}", new_fd);
            LinuxError::EMFILE
        })?;

        Ok(new_fd)
    })
}
/// Manipulate file descriptor.
///
/// TODO: `SET/GET` command is ignored, hard-code stdin/stdout
pub fn sys_fcntl(fd: c_int, cmd: c_int, arg: usize) -> c_int {
    debug!("sys_fcntl <= fd: {} cmd: {} arg: {}", fd, cmd, arg);
    syscall_body!(sys_fcntl, {
        match cmd as u32 {
            ctypes::F_DUPFD => dup_fd(fd),
            ctypes::F_DUPFD_CLOEXEC => {
                // TODO: Change fd flags
                dup_fd(fd)
            }
            ctypes::F_SETFL => {
                if fd == 0 || fd == 1 || fd == 2 {
                    return Ok(0);
                }
                get_file_like(fd)?.set_nonblocking(arg & (ctypes::O_NONBLOCK as usize) > 0)?;
                Ok(0)
            }
            _ => {
                warn!("unsupported fcntl parameters: cmd {}", cmd);
                Ok(0)
            }
        }
    })
}

pub fn ps2event(ps: &PollState) -> c_short {
    let mut events = 0;
    if ps.readable {
        events |= ctypes::POLLIN;
    }
    if ps.writable {
        events |= ctypes::POLLOUT;
    }
    events as c_short
}

/*
 *pub fn sys_ppoll(
 *    fds: *mut ctypes::pollfd,
 *    nfds: ctypes::nfds_t,
 *    // TODO: timeout_ts
 *    _timeout_ts: *const ctypes::timespec,
 *    // TODO: sigmask
 *    _sigmask: *const ctypes::sigset_t,
 *) -> c_int {
 *    syscall_body!(sys_ppoll, {
 *        let fds = unsafe { core::slice::from_raw_parts_mut(fds, nfds as usize) };
 *
 *        let mut ready_count = 0;
 *        loop {
 *            for fd in &mut *fds {
 *                match get_file_like(fd.fd) {
 *                    Ok(file_like) => match file_like.poll() {
 *                        Ok(poll_state) => {
 *                            debug!("poll_state: {:?}, fd: {fd:?}", poll_state);
 *                            fd.revents = ps2event(&poll_state);
 *                            ready_count += 1;
 *                        }
 *                        Err(_) => {
 *                            warn!("error polling file descriptor");
 *                            // Here we might want to set an error flag in revents
 *                            fd.revents = ctypes::POLLNVAL as c_short;
 *                            ready_count += 1;
 *                        }
 *                    },
 *                    Err(_) => {
 *                        warn!("invalid file descriptor");
 *                        fd.revents = ctypes::POLLNVAL as c_short;
 *                        ready_count += 1;
 *                    }
 *                }
 *            }
 *            if ready_count == 0 {
 *                yield_now();
 *            } else {
 *                break;
 *            }
 *        }
 *        Ok(ready_count)
 *    })
 *}
 */

pub fn sys_ppoll(
    fds: *mut ctypes::pollfd,
    nfds: ctypes::nfds_t,
    timeout_ts: *const ctypes::timespec,
    _sigmask: *const ctypes::sigset_t, // 暂不处理信号掩码
) -> c_int {
    syscall_body!(sys_ppoll, {
        if nfds == 0 {
            return Ok(0);
        }
        // 1. 处理超时参数
        let has_timeout = !timeout_ts.is_null();
        let timeout_duration = if has_timeout {
            let ts = unsafe { timeout_ts.as_ref().ok_or(LinuxError::EFAULT)? };
            // 检查立即返回的特殊情况（timeout=0）
            if ts.tv_sec == 0 && ts.tv_nsec == 0 {
                // 立即返回，不阻塞
                return poll_once(fds, nfds);
            }
            Some(Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32))
        } else {
            None // 无限等待
        };

        // 2. 记录开始时间
        let start_time = axhal::time::monotonic_time();
        let mut ready_count = 0;

        // 3. 主循环
        loop {
            // 执行一次poll检查
            ready_count = poll_once(fds, nfds)?;

            // 如果有就绪的文件描述符，立即返回
            if ready_count > 0 {
                return Ok(ready_count);
            }

            // 4. 检查超时
            if let Some(duration) = timeout_duration {
                let elapsed = axhal::time::monotonic_time() - start_time;
                if elapsed >= duration {
                    // 超时返回0
                    return Ok(0);
                }
            }

            // 5. 让出CPU，避免忙等待
            yield_now();
        }
    })
}

// 辅助函数：执行一次poll检查
fn poll_once(fds: *mut ctypes::pollfd, nfds: ctypes::nfds_t) -> LinuxResult<usize> {
    if nfds == 0 {
        return Ok(0);
    }

    let fds_slice = unsafe { core::slice::from_raw_parts_mut(fds, nfds as usize) };
    let mut ready_count = 0;

    for fd in fds_slice.iter_mut() {
        // 重置revents
        fd.revents = 0;

        match get_file_like(fd.fd) {
            Ok(file_like) => match file_like.poll() {
                Ok(poll_state) => {
                    let events = ps2event(&poll_state);
                    // 只返回请求的事件
                    fd.revents = events & fd.events;

                    if fd.revents != 0 {
                        ready_count += 1;
                    }
                }
                Err(e) => {
                    // 错误处理
                    // TODO:
                    fd.revents = match e {
                        _ => ctypes::POLLERR as c_short,
                    };
                    if fd.revents != 0 {
                        ready_count += 1;
                    }
                }
            },
            Err(_) => {
                // 无效文件描述符
                fd.revents = ctypes::POLLNVAL as c_short;
                ready_count += 1;
            }
        }
    }

    Ok(ready_count)
}

pub fn sys_copy_file_range(
    fd_in: c_int,
    off_in: *mut off_t,
    fd_out: c_int,
    off_out: *mut off_t,
    len: size_t,
    flags: c_uint,
) -> Result<isize, LinuxError> {
    debug!(
        "sys_copy_file_range <= {} {:?} {} {:?} {} {}",
        fd_in, off_in, fd_out, off_out, len, flags
    );
    if len == 0 {
        return Ok(0);
    }
    // 检查文件描述符是否有效
    let file_in = get_file_like(fd_in)?;
    let file_out = get_file_like(fd_out)?;
    let in_origin_offset = file_in.seek(SeekFrom::Current(0))? as off_t;
    let out_origin_offset = file_out.seek(SeekFrom::Current(0))? as off_t;

    // 确定源文件的读取位置
    let mut current_read_offset: off_t; // 用于内部计算的当前读取偏移
    let initial_read_offset: off_t; // 复制操作开始时的读取偏移
    let use_off_in = !off_in.is_null();
    if use_off_in {
        // 使用指定的偏移
        initial_read_offset = unsafe { *off_in };
        if initial_read_offset < 0 {
            return Err(LinuxError::EINVAL);
        }
    } else {
        // 使用文件当前偏移
        initial_read_offset = in_origin_offset
    }
    current_read_offset = initial_read_offset;

    // 确定目标文件的写入位置
    let mut current_write_offset: off_t; // 用于内部计算的当前写入偏移
    let initial_write_offset: off_t; // 复制操作开始时的写入偏移
    let use_off_out = !off_out.is_null();
    if use_off_out {
        // 使用指定的偏移
        initial_write_offset = unsafe { *off_out };
        if initial_write_offset < 0 {
            return Err(LinuxError::EINVAL);
        }
    } else {
        // 使用文件当前偏移
        initial_write_offset = out_origin_offset;
    }
    current_write_offset = initial_write_offset;
    debug!("sys_copy_file_range offset: in:{initial_read_offset}, out:{initial_write_offset}");

    // 获取源文件的大小
    let file_in_size = file_in.stat()?.st_size as off_t;

    // 如果读取位置超过源文件大小，直接返回0
    if current_read_offset >= file_in_size {
        return Ok(0);
    }

    // 计算实际可复制的字节数
    let mut bytes_to_copy = len;
    // 确保不会读取超过源文件末尾
    if current_read_offset + (bytes_to_copy as off_t) > file_in_size {
        bytes_to_copy = (file_in_size - current_read_offset) as usize;
    }

    if bytes_to_copy == 0 {
        return Ok(0);
    }

    // 分配缓冲区进行复制
    const BUFFER_SIZE: usize = 8192; // 每次读取/写入的块大小
    let mut total_copied: usize = 0;

    // 循环直到复制完所有请求的字节或源文件读取完毕
    while total_copied < bytes_to_copy {
        let chunk_size = core::cmp::min(BUFFER_SIZE, bytes_to_copy - total_copied);
        let mut buffer = vec![0u8; chunk_size];

        // 1. 设置源文件读取位置并读取数据
        file_in.seek(SeekFrom::Start(current_read_offset as u64))?;
        let bytes_read = file_in.read(&mut buffer)?;
        if bytes_read == 0 {
            // 源文件已无更多数据可读
            break;
        }

        // 2. 处理目标文件空洞：手动填充零
        let current_out_size = file_out.stat()?.st_size as off_t;
        if current_write_offset > current_out_size {
            // 需要填充的零字节数量
            let padding_len = (current_write_offset - current_out_size) as usize;
            let zero_buffer = vec![0u8; core::cmp::min(padding_len, BUFFER_SIZE)]; // 使用小块零缓冲区
            
            // 将文件指针移动到当前文件末尾
            file_out.seek(SeekFrom::Start(current_out_size as u64))?;
            
            let mut bytes_padded: usize = 0;
            while bytes_padded < padding_len {
                let write_len = core::cmp::min(zero_buffer.len(), padding_len - bytes_padded);
                let written = file_out.write(&zero_buffer[..write_len])?;
                if written == 0 {
                    // 写入失败或文件系统已满
                    return Err(LinuxError::EIO); // 或者其他适当的错误
                }
                bytes_padded += written;
            }
        }
        
        // 3. 设置目标文件写入位置并写入数据
        file_out.seek(SeekFrom::Start(current_write_offset as u64))?;
        let bytes_written = file_out.write(&buffer[..bytes_read])?;

        // 4. 更新内部偏移量和总复制字节数
        current_read_offset += bytes_written as off_t;
        current_write_offset += bytes_written as off_t;
        total_copied += bytes_written;

        if bytes_written < bytes_read {
            // 写入不完整，可能是磁盘已满或写入错误
            break;
        }
    }

    // 5. 更新外部提供的偏移指针
    if use_off_in {
        unsafe {
            *off_in = current_read_offset;
        }
        file_in.seek(SeekFrom::Start(in_origin_offset as u64))?;
    } else {
        // 如果不使用外部偏移，则更新文件描述符的内部偏移
        file_in.seek(SeekFrom::Start(current_read_offset as u64))?;
    }

    if use_off_out {
        unsafe {
            *off_out = current_write_offset;
        }
        file_out.seek(SeekFrom::Start(out_origin_offset as u64))?;
    } else {
        // 如果不使用外部偏移，则更新文件描述符的内部偏移
        file_out.seek(SeekFrom::Start(current_write_offset as u64))?;
    }

    Ok(total_copied as isize)
}

pub fn splice(
    fd_in: c_int,
    off_in: Option<*mut off_t>,
    fd_out: c_int,
    off_out: Option<*mut off_t>,
    len: size_t,
    flags: u32,
) -> Result<isize, LinuxError> {
    const PIPE_BUF_SIZE: usize = 256;
    if len == 0 {
        debug!("The length of the buffer is 0");
        return Ok(0);
    }

    let file_in = get_file_like(fd_in)?;
    let file_out = get_file_like(fd_out)?;

    // 判断是否是管道
    let is_pipe_in = file_in.is_pipe();
    let is_pipe_out = file_out.is_pipe();
    debug!(
        "splice: is_pipe_in = {}, is_pipe_out = {}",
        is_pipe_in, is_pipe_out
    );

    // splice 要求：必须一个是管道，另一个是普通文件
    if is_pipe_in == is_pipe_out {
        return Err(LinuxError::EINVAL);
    }

    let off_in_is_null = off_in.map_or(true, |p| p.is_null());
    let off_out_is_null = off_out.map_or(true, |p| p.is_null());

    if (is_pipe_in && !off_in_is_null) || (!is_pipe_in && off_in_is_null) {
        warn!("splice: invalid off_in for is_pipe_in={}", is_pipe_in);
        return Err(LinuxError::EINVAL);
    }
    if (is_pipe_out && !off_out_is_null) || (!is_pipe_out && off_out_is_null) {
        warn!("splice: invalid off_out for is_pipe_out={}", is_pipe_out);
        return Err(LinuxError::EINVAL);
    }
    // // 检查偏移合法性
    // if (is_pipe_in && off_in.is_some()) || (!is_pipe_in && off_in.is_none()) {
    //     return Err(LinuxError::EINVAL);
    // }
    // if (is_pipe_out && off_out.is_some()) || (!is_pipe_out && off_out.is_none()) {
    //     return Err(LinuxError::EINVAL);
    // }

    let mut offset_in = match (is_pipe_in, off_in) {
        (true, _) => 0,
        (false, Some(ptr)) if !ptr.is_null() => {
            let val = check_and_read_user_ptr(ptr)?;
            if val < 0 {
                return Err(LinuxError::EINVAL);
            }
            let file_size = file_in.stat().map_err(|_| LinuxError::EIO)?.st_size;
            debug!("got stat.st_size = {}", file_size);
            if val >= file_size {
                debug!("the val is larger than the file_size of {}", val);
                return Ok(0);
            }
            val as u64
        }
        _ => return Err(LinuxError::EFAULT),
    };

    let mut offset_out = if !is_pipe_out {
        let off_ptr = off_out.unwrap();
        check_and_read_user_ptr(off_ptr)? as u64
    } else {
        0
    };

    let buf_len = len.min(PIPE_BUF_SIZE);
    let mut buffer = vec![0u8; buf_len];

    // 读入数据
    let bytes_read = if is_pipe_in {
        file_in.read(&mut buffer)?
    } else {
        file_in.read_at(&mut buffer, offset_in)?
    };

    if bytes_read == 0 {
        debug!("the buffer is empty");
        return Ok(0);
    }

    // 写出数据
    let bytes_written = if is_pipe_out {
        file_out.write(&buffer[..bytes_read])?
    } else {
        file_out.write_at(&buffer[..bytes_read], offset_out)?
    };

    // 更新偏移
    if !is_pipe_in {
        let new_offset = offset_in + bytes_written as u64;
        unsafe {
            copy_to_user(off_in.unwrap(), &(new_offset as off_t))?;
        }
    }
    if !is_pipe_out {
        let new_offset = offset_out + bytes_written as u64;
        unsafe {
            copy_to_user(off_out.unwrap(), &(new_offset as off_t))?;
        }
    }

    Ok(bytes_written as isize)
}

#[ctor_bare::register_ctor]
fn init_stdio() {
    let mut fd_table = flatten_objects::FlattenObjects::new();
    fd_table
        .add_at(0, Arc::new(stdin()) as _)
        .unwrap_or_else(|_| panic!()); // stdin
    fd_table
        .add_at(1, Arc::new(stdout()) as _)
        .unwrap_or_else(|_| panic!()); // stdout
    fd_table
        .add_at(2, Arc::new(stdout()) as _)
        .unwrap_or_else(|_| panic!()); // stderr
    FD_TABLE.init_new(spin::RwLock::new(fd_table));
}
