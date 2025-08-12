use crate::ctype_my::statx;
use crate::ctypes;
use crate::imp::stdio::{stdin, stdout};
use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::vec;
use axerrno::{LinuxError, LinuxResult, ax_err};
use axfs_vfs::{VfsNodeAttr, VfsNodeOps, VfsResult};
use axio::PollState;
use axns::{ResArc, def_resource};
use axtask::yield_now;
use core::ffi::{c_char, c_int, c_short, c_void};
use core::time::Duration;
use flatten_objects::FlattenObjects;
use spin::Mutex;
use spin::{Once, RwLock};
use crate::ctypes::{off_t, size_t, ssize_t};
use crate::{utils::check_and_read_user_ptr,utils::write_back_user_ptr,
            utils::copy_to_user, utils::copy_from_user};
use axio::SeekFrom;
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

pub fn copy_file_range(
    fd_in: c_int,
    off_in: Option<*mut off_t>,
    fd_out: c_int,
    off_out: Option<*mut off_t>,
    size: size_t,
    flags: u32,
) -> Result<isize, LinuxError> {
    if flags != 0 {
        return Err(LinuxError::EINVAL);
    }
    let mut src = get_file_like(fd_in)?;
    let mut dst = get_file_like(fd_out)?;

    // TODO: 检查是否是可读/写
    // if !src.readable() || !dst.writable() {
    //     return Err(LinuxError::EBADF);
    // }

    let mut in_offset = if let Some(off_ptr) = off_in {
        let offset = check_and_read_user_ptr(off_ptr)?; // 用户提供 offset，系统不更新文件 offset
        Some(offset)
    } else {
        None // 使用文件自身偏移
    };
    let mut out_offset = if let Some(off_ptr) = off_out {
        let offset = check_and_read_user_ptr(off_ptr)?;
        Some(offset)
    } else {
        None
    };
    // 临时缓冲区
    const CHUNK_SIZE: usize = 4096;
    let mut total_copied = 0;
    let mut buffer = [0u8; CHUNK_SIZE];

    while total_copied < size {
        let to_read = core::cmp::min(CHUNK_SIZE, size - total_copied);

        // 读取 offset（处理 Option<i64>）
        let read_off = match in_offset {
            Some(v) => { if v < 0 { return Err(LinuxError::EINVAL); } v as u64 }
            None => src.seek(SeekFrom::Current(0))?,
        };

        let read_len = src.read_at(&mut buffer[..to_read], read_off)?;
        if read_len == 0 {break; }  // EOF

        let write_off = match out_offset {
            Some(v) => {if v < 0 { return Err(LinuxError::EINVAL); } v as u64 }
            None => dst.seek(SeekFrom::Current(0))?,
        };

        let written = dst.write_at(&buffer[..read_len], write_off)?;
        if written == 0 { break;}

        total_copied += written;

        // 更新 offset 变量
        if let Some(off) = in_offset.as_mut() {
            *off += written as i64;
        } else {
            src.seek(SeekFrom::Current(written as i64))?; // 修改文件 offset
        }

        if let Some(off) = out_offset.as_mut() {
            *off += written as i64;
        } else {
            dst.seek(SeekFrom::Current(written as i64))?;
        }
    }

    // 如果偏移指针是 Some，则写回修改后的偏移量
    if let Some(off_ptr) = off_in {
        write_back_user_ptr(off_ptr, in_offset.unwrap())?;
    }
    if let Some(off_ptr) = off_out {
        write_back_user_ptr(off_ptr, out_offset.unwrap())?;
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
    debug!("splice: is_pipe_in = {}, is_pipe_out = {}", is_pipe_in, is_pipe_out);

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
            if val >= file_size{
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
        unsafe {copy_to_user(off_in.unwrap(), &(new_offset as off_t))?;}
    }
    if !is_pipe_out {
        let new_offset = offset_out + bytes_written as u64;
        unsafe {copy_to_user(off_out.unwrap(), &(new_offset as off_t))?;}
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
