use crate::{SyscallResult, ToLinuxResult, result};
use arceos_posix_api::ctypes::{blkcnt_t, blksize_t, dev_t, gid_t, ino_t, mode_t, nlink_t, off_t, time_t, timespec, timeval, uid_t};
use arceos_posix_api::{self as api, char_ptr_to_str, ctypes};
use axfs::api::set_current_dir;
use axlog::debug;
use core::ffi::{c_char, c_int, c_long, c_longlong, c_void};
use axfs_vfs::FileSystemInfo;
// use ctype_my::statx;
use api::ctype_my::statx;
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct test_stat {
    pub st_dev: dev_t,
    pub st_ino: ino_t,
    pub st_mode: mode_t,
    pub st_nlink: nlink_t,
    pub st_uid: uid_t,
    pub st_gid: gid_t,
    pub st_rdev: dev_t,
    pub __pad1: u64,
    pub st_size: off_t,
    pub st_blksize: blksize_t,
    pub st_blocks: blkcnt_t,
    pub st_atime_sec: c_long,
    pub st_atime_nsec: c_long,
    pub st_mtime_sec: c_long,
    pub st_mtime_nsec: c_long,
    pub st_ctime_sec: c_long,
    pub st_ctime_nsec: c_long,
}

impl From<ctypes::stat> for test_stat {
    fn from(original: ctypes::stat) -> test_stat {
        test_stat {
            st_dev: original.st_dev,
            st_ino: original.st_ino,
            st_mode: original.st_mode,
            st_nlink: original.st_nlink,
            st_uid: original.st_uid,
            st_gid: original.st_gid,
            st_rdev: original.st_rdev,
            __pad1: 0,
            st_size: original.st_size,
            st_blksize: original.st_blksize,
            st_blocks: original.st_blocks,
            st_atime_sec: original.st_atime.tv_sec as c_long,
            st_mtime_sec: original.st_mtime.tv_sec as c_long,
            st_ctime_sec: original.st_ctime.tv_sec as c_long,
            st_atime_nsec: original.st_atime.tv_nsec as c_long,
            st_mtime_nsec: original.st_mtime.tv_nsec as c_long,
            st_ctime_nsec: original.st_ctime.tv_nsec as c_long,
        }
    }
}

#[inline]
pub fn sys_openat(
    dirfd: c_int,
    filename: *const c_char,
    flags: c_int,
    mode: ctypes::mode_t,
) -> SyscallResult {
    api::sys_openat(dirfd, filename, flags, mode).to_linux_result()
}

#[inline]
pub fn sys_lseek(fd: c_int, offset: ctypes::off_t, whence: c_int) -> SyscallResult {
    (api::sys_lseek(fd, offset, whence) as isize).to_linux_result()
}

// #[inline]
// pub unsafe fn sys_stat(path: *const c_char, buf: *mut ctypes::stat) -> SyscallResult {
//     api::sys_stat(path, buf).to_linux_result()
// }


#[inline]
pub unsafe fn sys_stat(path: *const c_char, buf: *mut test_stat) -> SyscallResult {
    let mut stat_buf = ctypes::stat::default();
    let result = api::sys_stat(path, &mut stat_buf as *mut _).to_linux_result();
    *buf = test_stat::from(stat_buf);
    result
}

#[inline]
pub unsafe fn sys_fstat(fd: c_int, buf: *mut test_stat) -> SyscallResult {
    let mut stat_buf = ctypes::stat::default();
    let result = unsafe { api::sys_fstat(fd, &mut stat_buf as *mut _) }.to_linux_result();
    *buf = test_stat::from(stat_buf);
    result
}


#[inline]
pub fn sys_renameat(
    olddfd: c_int,
    old: *const c_char,
    newdfd: c_int,
    new: *const c_char,
) -> SyscallResult {
    api::sys_renameat(olddfd, old, newdfd, new).to_linux_result()
}


#[inline]
pub unsafe fn sys_statx(
    dirfd: c_int,
    pathname: *const c_char,
    flags: c_int,
    mask: u32,
    statxbuf: *mut statx,
)->SyscallResult{
    unsafe{api::sys_statx(dirfd,pathname,flags,mask,statxbuf).map(|r| r as isize)}
}
// #[inline]
// pub unsafe fn sys_fstat(fd: c_int, buf: *mut ctypes::stat) -> SyscallResult {
//      unsafe { api::sys_fstat(fd,buf) }.to_linux_result()
// }
#[inline]
pub unsafe fn sys_fstatat(
    dir_fd: c_int,
    filename: *const c_char,
    buf: *mut ctypes::stat,
    flags: c_int,
) -> SyscallResult {
    unsafe { api::sys_fstatat(dir_fd, filename, buf, flags).map(|r| r as isize) }
}

#[inline]
pub unsafe fn sys_lstat(path: *const c_char, buf: *mut ctypes::stat) -> SyscallResult {
    api::sys_lstat(path, buf).to_linux_result()
}

#[inline]
pub fn sys_getcwd(buf: *mut c_char, size: usize) -> SyscallResult {
    (api::sys_getcwd(buf, size) as isize).to_linux_result()
}

#[inline]
pub fn sys_rename(old: *const c_char, new: *const c_char) -> SyscallResult {
    api::sys_rename(old, new).to_linux_result()
}

#[inline]
pub fn sys_mkdirat(dir_fd: usize, dir_path: *const c_char, mode: usize) -> SyscallResult {
    arceos_posix_api::sys_mkdirat(dir_fd as c_int, dir_path, mode.try_into().unwrap())
        .to_linux_result()
}

#[inline]
pub fn sys_chdir(path: *const c_char) -> SyscallResult {
    let ret = char_ptr_to_str(path).map(|chdir_path| set_current_dir(&chdir_path));
    match ret {
        Ok(_) => SyscallResult::Ok(0),
        Err(e) => SyscallResult::Err(e.into()),
    }
}

#[inline]
pub fn sys_getdents(fd: c_int, dirp: *mut ctypes::dirent, count: c_int) -> SyscallResult {
    unsafe { api::sys_getdents(fd, dirp, count) }
}

#[inline]
pub fn sys_unlink(path: *const c_char, flags: c_int) -> SyscallResult {
    api::sys_unlink(path, flags)
}

#[inline]
pub fn sys_unlinkat(dir_fd: c_int, path: *const c_char, flags: c_int) -> SyscallResult {
    api::sys_unlinkat(dir_fd, path, flags)
}

pub fn sys_fgetxattr(
    fd: c_int,
    name: *const c_char,
    buf: *mut c_void,
    sizes: usize
) -> SyscallResult { api::sys_fgetxattr(fd, name, buf, sizes).to_linux_result()}

pub fn sys_fsetxattr(
    fd: c_int,
    name: *const c_char,
    buf: *mut c_void,
    size: usize,
    flags: usize,
) -> SyscallResult {
    api::sys_fsetxattr(fd, name, buf, size, flags).to_linux_result()
}

pub fn sys_flistxattr(
    fd: c_int,
    list: *mut c_char,
    size: usize,
)->SyscallResult { api::sys_listxattr(fd, list, size).to_linux_result()}

pub fn sys_fremovexattr(
    fd: c_int,
    name: *const c_char
) -> SyscallResult {
    api::sys_fremovexattr(fd, name).to_linux_result()
}

pub fn sys_mount(src: *const c_char, mnt: *const c_char, fstype: *const c_char, mntflag: usize) -> SyscallResult {
    api::sys_mount(src, mnt, fstype, mntflag)
}

pub fn sys_umount2(mnt: *const c_char) -> SyscallResult {
    api::sys_umount2(mnt)
}

pub fn sys_utimesat(
    dirfd: c_int,
    path: *const c_char,
    times:*const timespec,
    now: timeval,
    flags: c_int
) -> SyscallResult {
   api::sys_utimensat(dirfd,path,times,now,flags)?.to_linux_result()
}

pub fn sys_pread64(
    fd: c_int,
    buf: *mut u8,
    count:usize,
    offset:isize
)->SyscallResult {
    api::sys_pread64(fd, buf, count, offset)?.to_linux_result()
}

pub fn sys_pwrite64(
    fd: c_int,
    buf: *const u8,
    count:usize,
    offset:isize
) -> SyscallResult{
    api::sys_pwrite64(fd, buf, count, offset)?.to_linux_result()
}

pub fn sys_statfs(
    _path: *const c_char,
    stat_fs:*mut FileSystemInfo
)->SyscallResult {
    api::sys_statfs(_path,stat_fs)?.to_linux_result()
}

pub fn sys_truncate(path: *const c_char, len: off_t) -> SyscallResult {
    api::sys_truncate(path, len)?.to_linux_result()
}
pub fn sys_ftruncate(fd: c_int, len: off_t) -> SyscallResult {
    api::sys_ftruncate(fd, len)?.to_linux_result()
}

pub fn sys_readlinkat(
    dirfd: c_int,
    pathname_p: *const c_char,
    buf: *mut c_char,
    bufsize: usize,
)->SyscallResult {
    api::sys_readlinkat(dirfd, pathname_p, buf, bufsize)?.to_linux_result()
}