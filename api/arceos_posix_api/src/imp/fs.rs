use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use axfs::CURRENT_DIR;
use axfs::api::{DirEntry, create_dir, current_dir, read_dir, remove_file};
use axfs::path::join;
use axfs::root::{ROOT_DIR, RootDirectory};
use axfs_vfs::{FileSystemInfo, VfsDirEntry, VfsNodeAttr, VfsNodeOps, VfsNodeType};
use core::ffi::{c_char, c_int, c_long, c_longlong, c_uint, c_void};
use core::str::from_utf8;
use core::{panic, ptr, slice};
use static_assertions::assert_eq_size;

use super::fd_ops::{FileLike, get_file_like};
use crate::ctype_my::{__u32, statx, statx_timestamp};
use crate::ctypes::{
    __IncompleteArrayField, AT_FDCWD, AT_REMOVEDIR, stat, time_t, timespec, timeval,
};
use axerrno::{LinuxError, LinuxResult};
use axfs::fops::OpenOptions;
use axfs_vfs::structs::VfsNodeAttrX;
use axio::{PollState, SeekFrom};
use axsync::Mutex;
// use crate::ctypes::{__IncompleteArrayField, time_t};
use crate::utils::str_to_cstr;
use crate::{ctypes, utils::char_ptr_to_str};
pub const UTIME_NOW: c_long = (1 << 30) - 1;
pub const UTIME_OMIT: c_long = (1 << 30) - 2;
const AT_EMPTY_PATH: c_int = 0x1000;
// use crate::time;
/// File wrapper for `axfs::fops::File`.
pub struct File {
    inner: Mutex<axfs::fops::File>,
    path: String,
}

impl File {
    fn new(inner: axfs::fops::File, path: String) -> Self {
        Self {
            inner: Mutex::new(inner),
            path,
        }
    }

    fn add_to_fd_table(self) -> LinuxResult<c_int> {
        super::fd_ops::add_file_like(Arc::new(self))
    }

    pub fn from_fd(fd: c_int) -> LinuxResult<Arc<Self>> {
        let f = super::fd_ops::get_file_like(fd)?;
        f.into_any()
            .downcast::<Self>()
            .map_err(|_| LinuxError::EINVAL)
    }

    /// Get the path of the file.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Get the inner node of the file.    
    pub fn inner(&self) -> &Mutex<axfs::fops::File> {
        &self.inner
    }
}

fn get_c_string_length(name: *const c_char) -> usize {
    if name.is_null() {
        return 0; // 如果指针为空，返回长度为 0
    }
    let mut len = 0;
    let mut ptr = name;
    unsafe {
        // 遍历指针，直到遇到空字符 \0
        while *ptr != 0 {
            len += 1;
            ptr = ptr.offset(1);
        }
    }
    len
}

impl FileLike for File {
    fn read(&self, buf: &mut [u8]) -> LinuxResult<usize> {
        Ok(self.inner.lock().read(buf)?)
    }

    fn write(&self, buf: &[u8]) -> LinuxResult<usize> {
        Ok(self.inner.lock().write(buf)?)
    }

    fn stat(&self) -> LinuxResult<ctypes::stat> {
        let metadata = self.inner.lock().get_attr()?;
        Ok(attr2stat(metadata))
    }

    fn statx(&self) -> LinuxResult<statx> {
        let metadata = self.inner.lock().get_attr_x()?;
        Ok(attr2statx(metadata))
    }

    fn read_at(&self, _buf: &mut [u8], _offset: u64) -> LinuxResult<usize> {
        self.inner
            .lock()
            .read_at(_offset, _buf)
            .map_err(LinuxError::from)
    }

    fn write_at(&self, _buf: &[u8], _offset: u64) -> LinuxResult<usize> {
        self.inner
            .lock()
            .write_at(_offset, _buf)
            .map_err(LinuxError::from)
    }

    fn set_atime(&self, atime: u32, atime_n: u32) -> LinuxResult<usize> {
        let r = self
            .inner
            .lock()
            .set_atime(atime, atime_n)
            .map_err(|_| LinuxError::EIO)?;
        Ok(r)
    }
    fn set_mtime(&self, mtime: u32, mtime_n: u32) -> LinuxResult<usize> {
        let r = self
            .inner
            .lock()
            .set_mtime(mtime, mtime_n)
            .map_err(|_| LinuxError::EIO)?;
        Ok(r)
    }
    fn into_any(self: Arc<Self>) -> Arc<dyn core::any::Any + Send + Sync> {
        self
    }

    fn poll(&self) -> LinuxResult<PollState> {
        Ok(PollState {
            readable: true,
            writable: true,
        })
    }

    fn set_nonblocking(&self, _nonblocking: bool) -> LinuxResult {
        Ok(())
    }

    fn fgetxattr(
        &self,
        name: *const c_char,
        buf: *mut c_void,
        buf_size: usize,
    ) -> LinuxResult<usize> {
        let name_len = get_c_string_length(name.clone());
        let data_size: *mut usize = &mut 0;
        Ok(self
            .inner
            .lock()
            .get_xattr(name, name_len, buf, buf_size, data_size)?)
    }

    fn flistxattr(&self, list: *mut c_char, size: usize) -> LinuxResult<usize> {
        let ret_size: *mut usize = &mut 0;
        self.inner.lock().list_xattr(list, size, ret_size)?;
        Ok(ret_size as usize)
    }
    fn fsetxattr(
        &self,
        name: *const c_char,
        value: *mut c_void,
        size: usize,
        flags: usize,
    ) -> LinuxResult<usize> {
        let name_len = get_c_string_length(name.clone());
        Ok(self.inner.lock().set_xattr(name, name_len, value, size)?)
    }

    fn fremovexattr(&self, name: *const c_char) -> LinuxResult<usize> {
        let name_len = get_c_string_length(name.clone());
        Ok(self.inner.lock().remove_xattr(name, name_len)?)
    }

    fn seek(&self, pos: SeekFrom) -> LinuxResult<u64> {
        Ok(self.inner.lock().seek(pos)?)
    }
}

fn attr2stat(metadata: VfsNodeAttr) -> ctypes::stat {
    let ty = metadata.file_type() as u8;
    let perm = metadata.perm().bits() as u32;
    let st_mode = ((ty as u32) << 12) | perm;
    ctypes::stat {
        st_dev: metadata.dev() as _,
        st_ino: metadata.st_ino() as _,
        st_mode,
        st_nlink: metadata.nlink() as _,
        st_uid: metadata.uid() as _,
        st_gid: metadata.gid() as _,
        st_size: metadata.size() as _,
        st_blksize: 512,
        st_blocks: metadata.blocks() as _,
        st_atime: timespec {
            tv_sec: metadata.atime() as time_t,
            tv_nsec: metadata.atime_nse() as core::ffi::c_long,
        },
        st_ctime: timespec {
            tv_sec: metadata.ctime() as time_t,
            tv_nsec: metadata.ctime_nse() as core::ffi::c_long,
        },
        st_mtime: timespec {
            tv_sec: metadata.mtime() as time_t,
            tv_nsec: metadata.mtime_nse() as core::ffi::c_long,
        },
        ..Default::default()
    }
}

fn attr2statx(metadata: VfsNodeAttrX) -> statx {
    let ty = metadata.file_type() as u8;
    let perm = metadata.stx_perm().bits() as u32;
    let stx_mode = ((ty as u32) << 12) | perm;
    let high: u16 = (stx_mode >> 16) as u16;
    let low: u16 = (stx_mode & 0xFFFF) as u16;
    statx {
        stx_mask: metadata.stx_mask() as _,
        stx_blksize: metadata.stx_blksize() as _,
        stx_attributes: metadata.stx_attributes() as _,
        stx_nlink: metadata.stx_nlink() as _,
        stx_uid: metadata.stx_uid() as _,
        stx_gid: metadata.stx_gid() as _,
        stx_mode: low as _,
        __spare0: [high] as _,
        stx_ino: metadata.stx_ino() as _,
        stx_size: metadata.stx_size() as _,
        stx_blocks: metadata.stx_blocks() as _,
        stx_attributes_mask: metadata.stx_attributes_mask() as _,
        stx_atime: statx_timestamp {
            tv_sec: metadata.atime() as time_t,
            tv_nsec: metadata.atime_nse() as __u32,
            __reserved: 0 as _,
        },
        stx_btime: statx_timestamp {
            tv_sec: metadata.ctime() as time_t,
            tv_nsec: metadata.ctime_nse() as __u32,
            __reserved: 0 as _,
        },
        stx_ctime: statx_timestamp {
            tv_sec: metadata.ctime() as time_t,
            tv_nsec: metadata.ctime_nse() as __u32,
            __reserved: 0 as _,
        },
        stx_mtime: statx_timestamp {
            tv_sec: metadata.mtime() as time_t,
            tv_nsec: metadata.mtime_nse() as __u32,
            __reserved: 0 as _,
        },
        stx_rdev_major: metadata.stx_rdev_major() as _,
        stx_rdev_minor: metadata.stx_rdev_minor() as _,
        stx_dev_major: metadata.stx_dev_major() as _,
        stx_dev_minor: metadata.stx_dev_minor() as _,
        ..Default::default()
    }
}

/// Convert open flags to [`OpenOptions`].
fn flags_to_options(flags: c_int, _mode: ctypes::mode_t) -> OpenOptions {
    let flags = flags as u32;
    let mut options = OpenOptions::new();
    match flags & 0b11 {
        ctypes::O_RDONLY => options.read(true),
        ctypes::O_WRONLY => options.write(true),
        _ => {
            options.read(true);
            options.write(true);
        }
    };
    if flags & ctypes::O_APPEND != 0 {
        options.append(true);
    }
    if flags & ctypes::O_TRUNC != 0 {
        options.truncate(true);
    }
    if flags & ctypes::O_CREAT != 0 {
        options.create(true);
    }
    if flags & ctypes::O_EXEC != 0 {
        //options.create_new(true);
        options.execute(true);
    }
    if flags & ctypes::O_DIRECTORY != 0 {
        options.directory(true);
    }
    options
}

/// Open a file by `filename` and insert it into the file descriptor table.
///
/// Return its index in the file table (`fd`). Return `EMFILE` if it already
/// has the maximum number of files open.
pub fn sys_open(filename: *const c_char, flags: c_int, mode: ctypes::mode_t) -> c_int {
    let filename = char_ptr_to_str(filename);
    debug!("sys_open <= {:?} {:#o} {:#o}", filename, flags, mode);
    syscall_body!(sys_open, {
        add_file_or_directory_fd(
            axfs::fops::File::open,
            axfs::fops::Directory::open_dir,
            filename?,
            &flags_to_options(flags, mode),
        )
    })
}

/// Open or create a file.
/// fd: file descriptor
/// filename: file path to be opened or created
/// flags: open flags
/// mode: see man 7 inode
/// return new file descriptor if succeed, or return -1.
pub fn sys_openat(
    dirfd: c_int,
    filename: *const c_char,
    flags: c_int,
    mode: ctypes::mode_t,
) -> c_int {
    let filename = match char_ptr_to_str(filename) {
        Ok(s) => s,
        Err(_) => return LinuxError::EFAULT as c_int,
    };

    debug!(
        "sys_openat <= {} {:?} {:#o} {:#o}",
        dirfd, filename, flags, mode
    );

    if filename.starts_with('/') || dirfd == AT_FDCWD as _ {
        return sys_open(filename.as_ptr() as _, flags, mode);
    }

    Directory::from_fd(dirfd)
        .and_then(|dir| {
            add_file_or_directory_fd(
                |filename, options| dir.inner.lock().open_file_at(filename, options),
                |filename, options| dir.inner.lock().open_dir_at(filename, options),
                filename,
                &flags_to_options(flags, mode),
            )
        })
        .unwrap_or_else(|e| {
            debug!("sys_openat => {}", e);
            -1
        })
}

/// Create a directory by `dirname` relatively to `dirfd`.
/// TODO: handle `mode`
pub fn sys_mkdirat(dirfd: c_int, dirname: *const c_char, mode: ctypes::mode_t) -> c_int {
    let dirname = match char_ptr_to_str(dirname) {
        Ok(s) => s,
        Err(_) => return -1,
    };

    debug!("sys_mkdirat <= {} {:?} {:#o}", dirfd, dirname, mode);

    if dirname.starts_with('/') || dirfd == AT_FDCWD as _ {
        return create_dir(dirname).and(Ok(0)).unwrap_or_else(|e| {
            debug!("sys_mkdirat => {}", e);
            -LinuxError::from(e).code()
        });
    }

    Directory::from_fd(dirfd)
        .and_then(|dir| {
            dir.inner.lock().create_dir(dirname);
            Ok(0)
        })
        .unwrap_or_else(|e| {
            debug!("sys_mkdirat => {}", e);
            -e.code()
        })
}

/// Create a directory by `dirname` relatively to `dirfd`.
/// TODO: handle `mode`
// pub unsafe fn sys_fstatat(
//     dirfd: c_int,
//     pathname_p: *const c_char,
//     statbuf: *mut ctypes::stat,
//     flags: c_int,
// ) -> LinuxResult<c_int> {
//     let pathname = char_ptr_to_str(pathname_p)?;
//
//     debug!(
//         "sys_fstatat <= {} {pathname_p:p} {:?} {:#o}",
//         dirfd, pathname, flags
//     );
//     debug!("{:?}", unsafe {
//         core::slice::from_raw_parts(pathname_p, 20)
//     });
//     static mut IDX: usize = 0;
//     unsafe {
//         if IDX == 7 {
//             //panic!()
//         }
//         IDX += 1;
//     }
//
//     if pathname.starts_with('/') || dirfd == AT_FDCWD as _ {
//         let dir = CURRENT_DIR.lock().clone();
//         let file = dir.lookup(pathname)?;
//         let stat = attr2stat(file.get_attr()?);
//         unsafe { *statbuf = stat };
//         return Ok(0);
//     }
//
//     let dir: Arc<Directory> = Directory::from_fd(dirfd)?;
//     // FIXME: correct path; flags
//     let file: File = File::new(
//         dir.inner
//             .lock()
//             .open_file_at(pathname, &flags_to_options(flags, 0))?,
//         pathname.into(),
//     );
//     let stat = file.stat()?;
//     unsafe { *statbuf = stat };
//     Ok(0)
// }
pub unsafe fn sys_fstatat(
    dirfd: c_int,
    pathname_p: *const c_char,
    statbuf: *mut ctypes::stat,
    flags: c_int,
) -> LinuxResult<c_int> {
    // 将 C 字符串转换为 Rust 字符串，并处理错误
    let pathname = match char_ptr_to_str(pathname_p) {
        Ok(s) => s,
        Err(e) => {
            debug!("sys_fstatat: failed to convert pathname: {:?}", e);
            return Err(e.into()); // 转换为 LinuxError
        }
    };

    debug!(
        "sys_fstatat <= {} {pathname_p:p} {:?} {:#o}",
        dirfd, pathname, flags
    );

    if flags & AT_EMPTY_PATH != 0 && pathname.is_empty() {
        return Ok(unsafe { sys_fstat(dirfd, statbuf) });
    }

    if pathname.starts_with('/') {
        let dir = ROOT_DIR.clone();
        let file = dir.lookup(pathname)?;
        let stat = attr2stat(file.get_attr()?);
        unsafe { *statbuf = stat };
        return Ok(0);
    }
    if dirfd == AT_FDCWD as _ {
        let dir = CURRENT_DIR.lock().clone();
        let file = match dir.lookup(pathname) {
            Ok(f) => f,
            Err(e) => {
                debug!("sys_fstatat: lookup failed for {}: {:?}", pathname, e);
                return Err(e.into()); // 转换为 LinuxError
            }
        };
        let attr = match file.get_attr() {
            Ok(a) => a,
            Err(e) => {
                debug!("sys_fstatat: get_attr failed for {}: {:?}", pathname, e);
                return Err(e.into()); // 转换为 LinuxError
            }
        };
        let stat = attr2stat(attr);
        unsafe { *statbuf = stat };
        return Ok(0);
    }

    // 处理相对路径
    let dir: Arc<Directory> = match Directory::from_fd(dirfd) {
        Ok(d) => d,
        Err(e) => {
            debug!("sys_fstatat: from_fd failed for dirfd {}: {:?}", dirfd, e);
            return Err(e.into()); // 转换为 LinuxError
        }
    };
    // 获取文件对象，处理 open_file_at 的 Result 返回值
    let inner_file = match dir
        .inner
        .lock()
        .open_file_at(pathname, &flags_to_options(flags, 0))
    {
        Ok(f) => f,
        Err(e) => {
            debug!("sys_fstatat: open_file_at failed for {}: {:?}", pathname, e);
            return Err(e.into()); // 转换为 LinuxError
        }
    };
    // 使用 inner_file 创建 File 实例，File::new 不返回 Result
    let file = File::new(inner_file, pathname.into());
    let stat = match file.stat() {
        Ok(s) => s,
        Err(e) => {
            debug!("sys_fstatat: stat failed for {}: {:?}", pathname, e);
            return Err(e.into()); // 转换为 LinuxError
        }
    };
    unsafe { *statbuf = stat };
    Ok(0)
}

/// Use the function to open file or directory, then add into file descriptor table.
/// First try opening files, if fails, try directory.
pub fn add_file_or_directory_fd<F, D, E>(
    open_file: F,
    open_dir: D,
    filename: &str,
    options: &OpenOptions,
) -> LinuxResult<c_int>
where
    E: Into<LinuxError>,
    F: FnOnce(&str, &OpenOptions) -> Result<axfs::fops::File, E>,
    D: FnOnce(&str, &OpenOptions) -> Result<axfs::fops::Directory, E>,
{
    if !options.has_directory() {
        match open_file(filename, options)
            .map_err(Into::into)
            .and_then(|f| File::new(f, filename.into()).add_to_fd_table())
        {
            Err(LinuxError::EISDIR) => {}
            r => return r,
        }
    }

    Directory::new(
        open_dir(filename, options).map_err(Into::into)?,
        filename.to_string(),
    )
    .add_to_fd_table()
}

/// Set the position of the file indicated by `fd`.
///
/// Return its position after seek.
pub fn sys_lseek(fd: c_int, offset: ctypes::off_t, whence: c_int) -> ctypes::off_t {
    debug!("sys_lseek <= {} {} {}", fd, offset, whence);
    syscall_body!(sys_lseek, {
        let pos = match whence {
            0 => SeekFrom::Start(offset as _),
            1 => SeekFrom::Current(offset as _),
            2 => SeekFrom::End(offset as _),
            _ => return Err(LinuxError::EINVAL),
        };
        let off = File::from_fd(fd)?.inner.lock().seek(pos)?;
        Ok(off)
    })
}

/// Get the file metadata by `path` and write into `buf`.
///
/// Return 0 if success.
pub unsafe fn sys_stat(path: *const c_char, buf: *mut ctypes::stat) -> c_int {
    let path = char_ptr_to_str(path);
    debug!("sys_stat <= {:?} {:#x}", path, buf as usize);
    syscall_body!(sys_stat, {
        if buf.is_null() {
            return Err(LinuxError::EFAULT);
        }
        let mut options = OpenOptions::new();
        options.read(true);
        let file = axfs::fops::File::open(path?, &options)?;
        let st = File::new(file, path?.to_string()).stat()?;
        unsafe { *buf = st };
        Ok(0)
    })
}

/// Get file metadata by `fd` and write into `buf`.
///
/// Return 0 if success.
pub unsafe fn sys_fstat(fd: c_int, buf: *mut ctypes::stat) -> c_int {
    debug!("sys_fstat <= {} {:#x}", fd, buf as usize);
    syscall_body!(sys_fstat, {
        if buf.is_null() {
            return Err(LinuxError::EFAULT);
        }
        unsafe { *buf = get_file_like(fd)?.stat()? };
        Ok(0)
    })
}

///Get the statx of the file in Loongarch64
pub unsafe fn sys_statx(
    dirfd: c_int,
    pathname_p: *const c_char,
    flags: c_int,
    mask: u32,
    statxbuf: *mut statx,
) -> LinuxResult<c_int> {
    let pathname = match char_ptr_to_str(pathname_p) {
        Ok(s) => s,
        Err(e) => {
            debug!("sys_statx: failed to convert pathname: {:?}", e);
            return Err(e.into()); // 转换为 LinuxError
        }
    };
    debug!(
        "sys_statx <= {} {pathname_p:p} {:?} {:#o}",
        dirfd, pathname, flags
    );
    if pathname.starts_with('/') {
        let dir = ROOT_DIR.clone();
        let file = dir.lookup(pathname)?;
        //TODO
        let statx = attr2statx(file.get_attr_x()?);
        //TODO:check the mask ivalid
        unsafe { *statxbuf = statx };
        return Ok(0);
    }
    if dirfd == AT_FDCWD as _ {
        let dir = CURRENT_DIR.lock().clone();
        let file = match dir.lookup(pathname) {
            Ok(f) => f,
            Err(e) => {
                debug!("sys_statx: lookup failed for {}: {:?}", pathname, e);
                return Err(e.into()); // 转换为 LinuxError
            }
        };
        let attr = match file.get_attr_x() {
            Ok(a) => a,
            Err(e) => {
                debug!("sys_statx: get_attr failed for {}: {:?}", pathname, e);
                return Err(e.into()); // 转换为 LinuxError
            }
        };
        let statx = attr2statx(attr);
        //TODO:check the mask ivalid
        unsafe { *statxbuf = statx };
        return Ok(0);
    }

    if pathname.is_empty() && (flags & AT_EMPTY_PATH as c_int) != 0 {
        let file_like = get_file_like(dirfd)?;
        let statx = match file_like.statx() {
            Ok(s) => s,
            Err(e) => {
                debug!("sys_statx: stat failed for dirfd {}: {:?}", dirfd, e);
                return Err(e.into());
            }
        };
        unsafe { *statxbuf = statx };
        return Ok(0);
    }

    // 处理相对路径
    let dir: Arc<Directory> = match Directory::from_fd(dirfd) {
        Ok(d) => d,
        Err(e) => {
            debug!("sys_statx: from_fd failed for dirfd {}: {:?}", dirfd, e);
            return Err(e.into()); // 转换为 LinuxError
        }
    };
    // 获取文件对象，处理 open_file_at 的 Result 返回值
    let inner_file = match dir
        .inner
        .lock()
        .open_file_at(pathname, &flags_to_options(flags, 0))
    {
        Ok(f) => f,
        Err(e) => {
            debug!("sys_statx: open_file_at failed for {}: {:?}", pathname, e);
            return Err(e.into()); // 转换为 LinuxError
        }
    };
    // 使用 inner_file 创建 File 实例，File::new 不返回 Result
    let file = File::new(inner_file, pathname.into());
    let statx = match file.statx() {
        Ok(s) => s,
        Err(e) => {
            debug!("sys_statx: stat failed for {}: {:?}", pathname, e);
            return Err(e.into()); // 转换为 LinuxError
        }
    };
    //TODO:check the mask ivalid
    unsafe { *statxbuf = statx };
    Ok(0)
}
/// Get the metadata of the symbolic link and write into `buf`.
///
/// Return 0 if success.
pub unsafe fn sys_lstat(path: *const c_char, buf: *mut ctypes::stat) -> ctypes::ssize_t {
    let path = char_ptr_to_str(path);
    debug!("sys_lstat <= {:?} {:#x}", path, buf as usize);
    syscall_body!(sys_lstat, {
        if buf.is_null() {
            return Err(LinuxError::EFAULT);
        }
        unsafe { *buf = Default::default() }; // TODO
        Ok(0)
    })
}

///get the xattr by fd and write into 'buf'
pub fn sys_fgetxattr(fd: c_int, name: *const c_char, buf: *mut c_void, sizes: usize) -> usize {
    debug!("sys_fgetxattr <= fd: {:?}, buf: {:#x}", fd, buf as usize);
    syscall_body!(sys_fgetxattr, {
        if fd < 0 {
            debug!("Invalid file descriptor: {}", fd);
            return Err(LinuxError::EBADF);
        }
        let file = get_file_like(fd).map_err(|e| {
            debug!("Failed to get File from fd {}: {:?}", fd, e);
            LinuxError::EBADF
        })?;
        if buf.is_null() {
            return Err(LinuxError::EINVAL);
        }
        file.fgetxattr(name, buf, sizes).map_err(|e| {
            debug!("Failed to get xattr: {:?}", e);
            e
        })
    })
}
///write the buf into  the xattr by fd
pub fn sys_fsetxattr(
    fd: c_int,
    name: *const c_char,
    buf: *mut c_void,
    size: usize,
    flags: usize,
) -> usize {
    debug!("sys_fsetxattr <= fd: {:?}, buf: {:#x}", fd, buf as usize);
    syscall_body!(sys_fsetxattr, {
        if fd < 0 {
            debug!("Invalid file descriptor: {}", fd);
            return Err(LinuxError::EBADF);
        }
        let file = get_file_like(fd).map_err(|e| {
            debug!("Failed to get File from fd {}: {:?}", fd, e);
            LinuxError::EBADF
        })?;
        if buf.is_null() {
            return Err(LinuxError::EINVAL);
        }
        file.fsetxattr(name, buf, size, flags).map_err(|e| {
            debug!("Failed to set xattr: {:?}", e);
            e
        })
    })
}
/// remove the axttr by fd
pub fn sys_fremovexattr(fd: c_int, name: *const c_char) -> usize {
    debug!(
        "sys_fremovexattr <= fd: {:?}, name: {:#x}",
        fd, name as usize
    );
    syscall_body!(sys_fremovexattr, {
        if fd < 0 {
            debug!("Invalid file descriptor: {}", fd);
            return Err(LinuxError::EBADF);
        }
        let file = get_file_like(fd).map_err(|e| {
            debug!("Failed to get File from fd {}: {:?}", fd, e);
            LinuxError::EBADF
        })?;
        file.fremovexattr(name).map_err(|e| {
            debug!("Failed to remove xattr: {:?}", e);
            e // Propagate the specific error (e.g., ENOATTR)
        })?;
        Ok(0)
    })
}

pub fn sys_listxattr(fd: c_int, list: *mut c_char, size: usize) -> usize {
    debug!("sys_listxattr <= fd: {:?}, list: {:#x}", fd, list as usize);
    syscall_body!(sys_listxattr, {
        if fd < 0 {
            debug!("Invalid file descriptor: {}", fd);
            return Err(LinuxError::EBADF);
        }
        let file = get_file_like(fd).map_err(|e| {
            debug!("Failed to get File from fd {}: {:?}", fd, e);
            LinuxError::EBADF
        })?;
        file.flistxattr(list, size).map_err(|e| {
            debug!("Failed to list xattr: {:?}", e);
            e // Propagate the specific error (e.g., ENOATTR)
        })?;
        Ok(0)
    })
}

/// Get the path of the current directory.
pub fn sys_getcwd(buf: *mut c_char, size: usize) -> *mut c_char {
    debug!("sys_getcwd <= {:#x} {}", buf as usize, size);
    syscall_body!(sys_getcwd, {
        if buf.is_null() {
            return Ok(core::ptr::null::<c_char>() as _);
        }
        let dst = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, size as _) };
        let cwd = axfs::api::current_dir()?;
        debug!("sys_getcwd >= {:?}", cwd);
        let cwd = cwd.as_bytes();
        if cwd.len() < size {
            dst[..cwd.len()].copy_from_slice(cwd);
            dst[cwd.len()] = 0;
            Ok(buf)
        } else {
            Err(LinuxError::ERANGE)
        }
    })
}

/// Rename `old` to `new`
/// If new exists, it is first removed.
///
/// Return 0 if the operation succeeds, otherwise return -1.
pub fn sys_rename(old: *const c_char, new: *const c_char) -> c_int {
    syscall_body!(sys_rename, {
        let old_path = char_ptr_to_str(old)?;
        let new_path = char_ptr_to_str(new)?;
        debug!("sys_rename <= old: {:?}, new: {:?}", old_path, new_path);
        axfs::api::rename(old_path, new_path)?;
        Ok(0)
    })
}

/// Rename `old` to `new`
/// If new exists, it is first removed.
///
/// Return 0 if the operation succeeds, otherwise return -1.
pub fn sys_renameat(
    old_dirfd: c_int,
    old: *const c_char,
    new_dirfd: c_int,
    new: *const c_char,
) -> c_int {
    syscall_body!(sys_rename, {
        let old_path = char_ptr_to_str(old)?;
        let new_path = char_ptr_to_str(new)?;
        // 处理相对路径的情况
        let old_path = if old_path.starts_with('/') {
            // 如果是绝对路径，直接使用
            old_path.to_string()
        } else if old_dirfd == AT_FDCWD as i32 {
            // 如果 old_dirfd 是 AT_FDCWD，则相对于当前工作目录解析
            current_dir()
                .map(|cwd| join(cwd.as_str(), &[old_path]))
                .unwrap_or(old_path.to_string())
        } else {
            // 否则，相对于 old_dirfd 指向的目录解析
            match Directory::from_fd(old_dirfd) {
                Ok(old_dir) => join(old_dir.path(), &[old_path]),
                Err(_) => return Err(LinuxError::EBADF), // 无效的文件描述符
            }
        };
        /*
         *let old_path = if old_path.starts_with('/') || old_dirfd == AT_FDCWD as i32 {
         *    old_path.to_string()
         *} else {
         *    match Directory::from_fd(old_dirfd) {
         *        Ok(old_dir) => join(old_dir.path(), &[old_path]),
         *        Err(_) => return Err(LinuxError::EBADF), // 无效的文件描述符
         *    }
         *};
         */
        // 处理新路径的情况
        let new_path = if new_path.starts_with('/') {
            new_path.to_string()
        } else if new_dirfd == AT_FDCWD as i32 {
            current_dir()
                .map(|cwd| join(cwd.as_str(), &[new_path]))
                .unwrap_or(new_path.to_string())
        } else {
            match Directory::from_fd(new_dirfd) {
                Ok(new_dir) => join(new_dir.path(), &[new_path]),
                Err(_) => return Err(LinuxError::EBADF), // 无效的文件描述符
            }
        };
        debug!("sys_rename <= old: {:?}, new: {:?}", old_path, new_path);
        axfs::api::rename(&old_path, &new_path)?;
        Ok(0)
    })
}
/// Directory wrapper for `axfs::fops::Directory`.
pub struct Directory {
    inner: Mutex<axfs::fops::Directory>,
    path: String,
}

impl Directory {
    fn new(inner: axfs::fops::Directory, path: String) -> Self {
        Self {
            inner: Mutex::new(inner),
            path,
        }
    }

    fn add_to_fd_table(self) -> LinuxResult<c_int> {
        super::fd_ops::add_file_like(Arc::new(self))
    }

    /// Open a directory by `fd`.
    pub fn from_fd(fd: c_int) -> LinuxResult<Arc<Self>> {
        let f = super::fd_ops::get_file_like(fd)?;
        f.into_any()
            .downcast::<Self>()
            .map_err(|_| LinuxError::EINVAL)
    }

    /// Get the path of the directory.
    pub fn path(&self) -> &str {
        &self.path
    }
}

impl FileLike for Directory {
    fn read(&self, _buf: &mut [u8]) -> LinuxResult<usize> {
        Err(LinuxError::EBADF)
    }

    fn write(&self, _buf: &[u8]) -> LinuxResult<usize> {
        Err(LinuxError::EBADF)
    }

    fn stat(&self) -> LinuxResult<ctypes::stat> {
        let metadata = self.inner.lock().get_attr()?;
        let ty = metadata.file_type() as u8;
        let perm = metadata.perm().bits() as u32;
        let st_mode = ((ty as u32) << 12) | perm;
        Ok(ctypes::stat {
            st_ino: metadata.st_ino() as u64,
            st_nlink: metadata.nlink(),
            st_mode,
            st_uid: metadata.uid() as c_uint,
            st_gid: metadata.gid() as c_uint,
            st_size: metadata.size() as _,
            //st_blocks: metadata.blocks() as _,
            st_blocks: metadata.blocks() as _,
            st_blksize: 512,
            ..Default::default()
        })
    }

    fn statx(&self) -> LinuxResult<statx> {
        let metadata = self.inner.lock().get_attr_x()?;
        Ok(attr2statx(metadata))
    }

    fn into_any(self: Arc<Self>) -> Arc<dyn core::any::Any + Send + Sync> {
        self
    }

    fn poll(&self) -> LinuxResult<PollState> {
        Ok(PollState {
            readable: true,
            writable: false,
        })
    }

    fn set_nonblocking(&self, _nonblocking: bool) -> LinuxResult {
        Ok(())
    }

    fn set_atime(&self, atime: u32, atime_n: u32) -> LinuxResult<usize> {
        let r = self
            .inner
            .lock()
            .set_atime(atime, atime_n)
            .map_err(|_| LinuxError::EIO)?;
        Ok(r)
    }
    fn set_mtime(&self, mtime: u32, mtime_n: u32) -> LinuxResult<usize> {
        let r = self
            .inner
            .lock()
            .set_mtime(mtime, mtime_n)
            .map_err(|_| LinuxError::EIO)?;
        Ok(r)
    }

    fn fgetxattr(
        &self,
        name: *const c_char,
        buf: *mut c_void,
        buf_size: usize,
    ) -> LinuxResult<usize> {
        let name_len = get_c_string_length(name.clone());
        let data_size: *mut usize = &mut 0;
        Ok(self
            .inner
            .lock()
            .get_xattr(name, name_len, buf, buf_size, data_size)?)
    }
    fn flistxattr(&self, list: *mut c_char, size: usize) -> LinuxResult<usize> {
        let ret_size: *mut usize = &mut 0;
        self.inner.lock().list_xattr(list, size, ret_size)?;
        Ok(ret_size as usize)
    }
    fn fsetxattr(
        &self,
        name: *const c_char,
        value: *mut c_void,
        size: usize,
        flags: usize,
    ) -> LinuxResult<usize> {
        let name_len = get_c_string_length(name.clone());
        Ok(self.inner.lock().set_xattr(name, name_len, value, size)?)
    }
    fn fremovexattr(&self, name: *const c_char) -> LinuxResult<usize> {
        let name_len = get_c_string_length(name.clone());
        Ok(self.inner.lock().remove_xattr(name, name_len)?)
    }
}

/*
 *pub unsafe fn sys_getdents(
 *    dir_fd: i32,
 *    buf: *mut ctypes::dirent,
 *    count: c_int,
 *) -> LinuxResult<isize> {
 *    let dir: Arc<Directory> = Directory::from_fd(dir_fd)?;
 *    let mut curr_dent = buf;
 *    let count = count.try_into().map_err(|_| LinuxError::EINVAL)?;
 *    let mut inner = dir.inner.lock();
 *    let end = (buf as *const u8).wrapping_add(count);
 *    let dirent_size = core::mem::size_of::<ctypes::dirent>();
 *    // TODO: support file name longer than 64 bytes
 *    // 64 : sizeof [char; 64];
 *    let mut nread = 0;
 *    while (curr_dent as *const u8).wrapping_add(dirent_size + 64) < end {
 *        let mut dirent_buf = [VfsDirEntry::default()];
 *        match inner.read_dir(&mut dirent_buf) {
 *            Ok(n) if n == 0 => break,
 *            Ok(n) => nread += n,
 *            Err(_) => break,
 *        }
 *        let name = dirent_buf[0].name_as_bytes();
 *        let name = unsafe { String::from_utf8_lossy(name) };
 *        assert!(name.len() < 64);
 *        let d_reclen = core::mem::size_of::<ctypes::dirent>() + name.len() + 1;
 *        unsafe {
 *            *curr_dent = ctypes::dirent {
 *                d_ino: 1,
 *                d_off: 0,
 *                d_reclen: d_reclen as u16,
 *                d_type: dirent_buf[0].entry_type() as u8,
 *                d_name: __IncompleteArrayField::<c_char>::new(),
 *            };
 *            let mut name_ptr = (curr_dent as *mut c_char).wrapping_add(19); // offset of d_name in dirent
 *            let str_len = str_to_cstr(&name, name_ptr);
 *            // FIXME: align struct??
 *            curr_dent = name_ptr.wrapping_add(str_len) as *mut _;
 *        };
 *        // cut off d_name at `\0`
 *    }
 *
 *    return Ok(nread as isize);
 *}
 */
// pub unsafe fn sys_getdents(
//     dir_fd: i32,
//     buf: *mut ctypes::dirent,
//     count: c_int,
// ) -> LinuxResult<isize> {
//     const MAX_NAME_LEN: usize = 255; // Linux NAME_MAX
//     const DIRENT_MIN_SIZE: usize = core::mem::size_of::<ctypes::dirent>();
//
//     let dir = Directory::from_fd(dir_fd)?;
//     let mut inner = dir.inner.lock();
//
//     let buf_start = buf as *const u8;
//     let buf_end = buf_start.wrapping_add(count as usize);
//     let mut curr_ptr = buf as *mut u8;
//     let mut entries_written = 0;
//
//     // Temporary buffer for directory entries
//     let mut dirent_buf = [VfsDirEntry::default(); 1];
//
//     loop {
//         // Check remaining space (need space for struct + name + null terminator)
//         let remaining = buf_end as usize - curr_ptr as usize;
//         if remaining < DIRENT_MIN_SIZE + MAX_NAME_LEN + 1 {
//             break;
//         }
//
//         // Read next directory entry
//         match inner.read_dir(&mut dirent_buf) {
//             Ok(0) => break, // No more entries
//             Ok(_) => (),
//             Err(e) => {
//                 if entries_written == 0 {
//                     return Err(e.into());
//                 }
//                 break;
//             }
//         }
//
//         let entry = &dirent_buf[0];
//         let name = entry.name_as_bytes();
//         let name_len = name.len().min(MAX_NAME_LEN);
//
//         // Calculate required space
//         let reclen = core::mem::align_of::<ctypes::dirent>()
//             .max(8)
//             .max(DIRENT_MIN_SIZE + name_len + 1);
//
//         if (curr_ptr as usize + reclen) > buf_end as usize {
//             break;
//         }
//
//         // Fill dirent structure
//         let dirent = curr_ptr as *mut ctypes::dirent;
//         unsafe {
//             (*dirent).d_ino = 1;
//             (*dirent).d_off = 0;
//             (*dirent).d_reclen = reclen as u16;
//             (*dirent).d_type = entry.entry_type() as u8;
//
//             // Copy name (including null terminator)
//             let name_dst = (*dirent).d_name.as_mut_ptr();
//             core::ptr::copy_nonoverlapping(name.as_ptr(), name_dst as *mut u8, name_len);
//             *name_dst.add(name_len) = 0;
//
//             curr_ptr = curr_ptr.add(reclen);
//         }
//         entries_written += 1;
//     }
//
//     Ok(if entries_written > 0 {
//         (curr_ptr as usize - buf_start as usize) as isize
//     } else {
//         0
//     })
// }
pub unsafe fn sys_getdents(
    dir_fd: i32,
    buf: *mut ctypes::dirent,
    count: c_int,
) -> LinuxResult<isize> {
    const MAX_NAME_LEN: usize = 255; // Linux NAME_MAX
    const DIRENT_MIN_SIZE: usize = core::mem::size_of::<ctypes::dirent>();
    const BATCH_SIZE: usize = 128; // 大幅增加批量读取目录项数量以提高性能

    let dir = Directory::from_fd(dir_fd)?;
    let mut inner = dir.inner.lock();

    let buf_start = buf as *const u8;
    let buf_end = buf_start.wrapping_add(count as usize);
    let mut curr_ptr = buf as *mut u8;
    let mut entries_written = 0;

    // 获取当前读取进度
    let start_idx = inner.get_entry_index();

    // 使用 Vec 作为临时缓冲区
    let mut dirent_buf: Vec<VfsDirEntry> = Vec::with_capacity(BATCH_SIZE);

    // 清空之前的缓冲区内容
    dirent_buf.clear();

    // 手动填充缓冲区
    for _ in 0..BATCH_SIZE {
        dirent_buf.push(VfsDirEntry::default());
    }

    // 一次性读取大量目录项
    let num_entries = match inner.read_dir(&mut dirent_buf) {
        Ok(n) => n,
        Err(e) => {
            return if entries_written == 0 {
                Err(e.into())
            } else {
                Ok(entries_written as isize)
            };
        }
    };

    if num_entries == 0 {
        return Ok(0); // 没有更多目录项
    }

    // 重置读取进度，以便在处理过程中追踪
    inner.set_entry_index(start_idx);

    // 处理批量读取的每个目录项
    for i in 0..num_entries {
        let entry = &dirent_buf[i];
        let name = entry.name_as_bytes();
        let name_len = name.len().min(MAX_NAME_LEN);

        // 动态计算所需空间
        let reclen = (DIRENT_MIN_SIZE + name_len + 1 + 7) & !7; // 对齐到8字节

        // 检查缓冲区空间是否足够
        if (curr_ptr as usize + reclen) > buf_end as usize {
            // 空间不足，设置进度到当前位置，确保下次从这里继续读取
            inner.set_entry_index(start_idx + i);
            break;
        }

        // 填充 dirent 结构
        let dirent = curr_ptr as *mut ctypes::dirent;
        unsafe {
            (*dirent).d_ino = 1;
            (*dirent).d_off = 0;
            (*dirent).d_reclen = reclen as u16;
            (*dirent).d_type = entry.entry_type() as u8;

            // 复制文件名（包括空终止符）
            let name_dst = (*dirent).d_name.as_mut_ptr();
            core::ptr::copy_nonoverlapping(name.as_ptr(), name_dst as *mut u8, name_len);
            *name_dst.add(name_len) = 0;

            curr_ptr = curr_ptr.add(reclen);
        }
        entries_written += 1;

        // 更新进度（重要：确保即使在内部循环中也会更新进度）
        inner.set_entry_index(start_idx + i + 1);
    }

    Ok((curr_ptr as usize - buf_start as usize) as isize)
}

pub fn sys_unlink(path: *const c_char, flags: c_int) -> LinuxResult<isize> {
    let path = char_ptr_to_str(path).map_err(|_| LinuxError::EFAULT)?;
    warn!("sys_unlink <= {:?}", path);
    if flags & AT_REMOVEDIR as i32 != 0 {
        read_dir(path)?;
    } else {
        remove_file(path)?;
    }
    Ok(0)
}
pub fn sys_unlinkat(dir_fd: i32, path: *const c_char, flags: c_int) -> LinuxResult<isize> {
    if dir_fd == AT_FDCWD {
        return sys_unlink(path, flags);
    }
    let dir: Arc<Directory> = Directory::from_fd(dir_fd)?;
    let path = char_ptr_to_str(path).map_err(|_| LinuxError::EFAULT)?;
    warn!("sys_unlinkat <= {dir_fd} {:?}", path);
    if flags & AT_REMOVEDIR as i32 != 0 {
        dir.inner.lock().remove_dir(path)?;
    } else {
        dir.inner.lock().remove_file(path)?;
    }
    Ok(0)
}

pub fn sys_mount(
    src: *const c_char,
    mnt: *const c_char,
    fstype: *const c_char,
    mntflag: usize,
) -> LinuxResult<isize> {
    debug!("mount simple return");
    Ok(0)
}

pub fn sys_umount2(mnt: *const c_char) -> LinuxResult<isize> {
    debug!("umount2 simple return");
    Ok(0)
}

pub fn parse_time(ts: &timespec, now: timeval) -> Result<Option<(u32, u32)>, LinuxError> {
    match ts.tv_nsec {
        x if x == UTIME_NOW as i64 => {
            let nsec = (now.tv_usec as i64) * 1000;
            // 检查 tv_sec 和 nsec 是否在 u32 范围内
            if now.tv_sec < 0 || now.tv_sec > u32::MAX as i64 || nsec < 0 || nsec > u32::MAX as i64
            {
                return Err(LinuxError::EINVAL);
            }
            Ok(Some((now.tv_sec as u32, nsec as u32)))
        }
        x if x == UTIME_OMIT as i64 => Ok(None),
        _ => {
            if ts.tv_nsec < 0 || ts.tv_nsec >= 1_000_000_000 {
                return Err(LinuxError::EINVAL);
            }
            // 检查 tv_sec 和 tv_nsec 是否在 u32 范围内
            if ts.tv_sec < 0 || ts.tv_sec > u32::MAX as i64 || ts.tv_nsec > u32::MAX as i64 {
                return Err(LinuxError::EINVAL);
            }
            Ok(Some((ts.tv_sec as u32, ts.tv_nsec as u32)))
        }
    }
}
fn extract_times(
    times: *const timespec,
    now: timeval,
) -> Result<(Option<(u32, u32)>, Option<(u32, u32)>), LinuxError> {
    if !times.is_null() {
        unsafe {
            let atime_result = parse_time(&*times, now)?;
            let mtime_result = parse_time(&*times.add(1), now)?;
            Ok((atime_result, mtime_result))
        }
    } else {
        let now_ts = timespec {
            tv_sec: now.tv_sec,
            tv_nsec: (now.tv_usec as i64) * 1000, // 微秒转纳秒
        };
        if now_ts.tv_nsec < 0 || now_ts.tv_nsec >= 1_000_000_000 {
            return Err(LinuxError::EINVAL);
        }
        let result = parse_time(&now_ts, now)?;
        Ok((result, result))
    }
}

pub fn sys_utimensat(
    dirfd: c_int,
    path: *const c_char,
    times: *const timespec,
    now: timeval,
    flags: c_int,
) -> LinuxResult<isize> {
    debug!("syscall sys_utimensat<={},{:?},{:?}", dirfd, path, times);
    let (atime_opt, mtime_opt) = extract_times(times, now)?;
    if !path.is_null() {
        let pathname = char_ptr_to_str(path).map_err(|_| LinuxError::EBADF)?;
        if dirfd == AT_FDCWD as i32 {
            let dir = CURRENT_DIR.lock().clone();
            let file = dir.lookup(pathname).map_err(|e| {
                debug!("lookup failed: {:?}", e);
                match e {
                    _ => LinuxError::ENOENT,
                }
            })?;
            if let Some((sec, nsec)) = atime_opt {
                file.set_atime(sec, nsec).map_err(|_| LinuxError::EIO)?;
            }
            if let Some((sec, nsec)) = mtime_opt {
                file.set_mtime(sec, nsec).map_err(|_| LinuxError::EIO)?;
            }
            return Ok(0);
        }
        if dirfd < 0 {
            return Err(LinuxError::EBADF);
        }
        let dir: Arc<Directory> = Directory::from_fd(dirfd).map_err(|_| LinuxError::EBADF)?;
        let file: File = File::new(
            dir.inner
                .lock()
                .open_file_at(pathname, &flags_to_options(flags, 0))
                .map_err(|e| {
                    debug!("open_file_at failed: {:?}", e);
                    match e {
                        _ => LinuxError::ENOENT,
                    }
                })?,
            pathname.into(),
        );
        if let Some((sec, nsec)) = atime_opt {
            file.set_atime(sec, nsec).map_err(|_| LinuxError::EIO)?;
        }
        if let Some((sec, nsec)) = mtime_opt {
            file.set_mtime(sec, nsec).map_err(|_| LinuxError::EIO)?;
        }
        Ok(0)
    } else {
        if dirfd < 0 {
            return Err(LinuxError::EBADF);
        }
        let file = get_file_like(dirfd).map_err(|_| LinuxError::EBADF)?;
        if let Some((sec, nsec)) = atime_opt {
            file.set_atime(sec, nsec).map_err(|_| LinuxError::EIO)?;
        }
        if let Some((sec, nsec)) = mtime_opt {
            file.set_mtime(sec, nsec).map_err(|_| LinuxError::EIO)?;
        }
        Ok(0)
    }
}

pub fn sys_pread64(fd: c_int, buf: *mut u8, count: usize, offset: isize) -> LinuxResult<isize> {
    let file = get_file_like(fd).map_err(|_| LinuxError::EBADF)?;
    let mut slice = unsafe { slice::from_raw_parts_mut(buf, count) };
    file.read_at(slice, offset as u64).map(|n| n as isize)
}

pub fn sys_pwrite64(fd: c_int, buf: *const u8, count: usize, offset: isize) -> LinuxResult<isize> {
    let file = get_file_like(fd).map_err(|_| LinuxError::EBADF)?;
    let mut slice = unsafe { slice::from_raw_parts(buf, count) };
    file.write_at(slice, offset as u64).map(|n| n as isize)
}

pub unsafe fn c_char_to_str(c_str: *const c_char) -> Result<&'static str, LinuxError> {
    if c_str.is_null() {
        return Err(LinuxError::EINVAL); // 或其它适当错误
    }
    let mut len = 0;
    while *c_str.add(len) != 0 {
        len += 1;
    }
    let bytes = slice::from_raw_parts(c_str as *const u8, len);
    from_utf8(bytes).map_err(|_| LinuxError::EINVAL) // 或其它编码错误
}
pub fn sys_statfs(mount_point: *const c_char, stat_fs: *mut FileSystemInfo) -> LinuxResult<isize> {
    let path = unsafe { c_char_to_str(mount_point.clone())? };
    let (mountpoint, fs) = ROOT_DIR.find_mountpoint_and_fs(path)?;
    let ret = fs.statfs(mount_point, stat_fs)?;
    Ok(ret as isize)
}
