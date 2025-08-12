//! POSIX-compatible APIs for [ArceOS] modules
//!
//! [ArceOS]: https://github.com/arceos-org/arceos

#![cfg_attr(all(not(test), not(doc)), no_std)]
#![feature(doc_cfg)]
#![feature(doc_auto_cfg)]
#![allow(clippy::missing_safety_doc)]

#[macro_use]
extern crate axlog;
extern crate axruntime;

#[cfg(feature = "alloc")]
extern crate alloc;

#[macro_use]
mod utils;

mod imp;
pub use utils::{char_ptr_to_str, str_vec_ptr_to_str};

/// Platform-specific constants and parameters.
pub mod config {
    pub use axconfig::*;
}

pub mod ctype_my;

/// POSIX C types.
#[rustfmt::skip]
#[path = "./ctypes_gen.rs"]
#[allow(dead_code, non_snake_case, non_camel_case_types, non_upper_case_globals, clippy::upper_case_acronyms, missing_docs)]
pub mod ctypes;

pub use imp::io::{sys_read, sys_readv, sys_write, sys_writev};
#[cfg(feature = "fs")]
pub use imp::path_link::{FilePath, HARDLINK_MANAGER, handle_file_path};
pub use imp::resources::{sys_getrlimit, sys_prlimit64, sys_setrlimit};
pub use imp::sys::{UtsName, sys_sysconf, sys_uname, SysInfo, sys_sysinfo, sys_getrandom};
pub use imp::task::{sys_exit, sys_getpid, sys_sched_yield};
pub use imp::time::{sys_clock_gettime, sys_get_time_of_day, sys_nanosleep};

#[cfg(feature = "fd")]
pub use imp::fd_ops::{
    FD_TABLE, FileLike, add_file_like, get_file_like, ps2event, sys_close, sys_dup, sys_dup2,
    sys_fcntl, sys_ppoll, copy_file_range, splice,
};
//#[cfg(feature = "fs")]
pub use imp::fs::{
    Directory, File, add_file_or_directory_fd, sys_fgetxattr, sys_fremovexattr, sys_fsetxattr,
    sys_fstat, sys_fstatat, sys_getcwd, sys_getdents, sys_listxattr, sys_lseek, sys_lstat,
    sys_mkdirat, sys_mount, sys_open, sys_openat, sys_pread64, sys_pwrite64, sys_rename,
    sys_renameat, sys_stat, sys_statfs, sys_statx, sys_umount2, sys_unlink, sys_unlinkat,
    sys_utimensat,sys_truncate, sys_ftruncate, sys_readlink, sys_readlinkat,
};
#[cfg(feature = "select")]
pub use imp::io_mpx::{FdSets, set_fd_set, sys_select, zero_fd_set};
#[cfg(feature = "epoll")]
pub use imp::io_mpx::{sys_epoll_create, sys_epoll_ctl, sys_epoll_wait};
#[cfg(feature = "net")]
pub use imp::net::{
    sys_accept, sys_bind, sys_connect, sys_freeaddrinfo, sys_getaddrinfo, sys_getpeername,
    sys_getsockname, sys_listen, sys_recv, sys_recvfrom, sys_send, sys_sendto, sys_shutdown,
    sys_socket,
};
#[cfg(feature = "pipe")]
pub use imp::pipe::sys_pipe;
#[cfg(feature = "multitask")]
pub use imp::pthread::mutex::{
    sys_pthread_mutex_init, sys_pthread_mutex_lock, sys_pthread_mutex_unlock,
};
#[cfg(feature = "multitask")]
pub use imp::pthread::{sys_pthread_create, sys_pthread_exit, sys_pthread_join, sys_pthread_self};
