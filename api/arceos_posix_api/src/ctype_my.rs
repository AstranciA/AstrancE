use core::ffi::*;
use core::default::Default;
pub type __u16 = c_ushort;
pub type __s32 = c_int;
pub type __u32 = c_uint;
pub type __s64 = c_longlong;
pub type __u64 = c_ulonglong;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct statx_timestamp {
    pub tv_sec: __s64,
    pub tv_nsec: __u32,
    pub __reserved: __s32,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct statx {
    pub stx_mask: __u32,
    pub stx_blksize: __u32,
    pub stx_attributes: __u64,
    pub stx_nlink: __u32,
    pub stx_uid: __u32,
    pub stx_gid: __u32,
    pub stx_mode: __u16,
    pub __spare0: [__u16; 1usize],
    pub stx_ino: __u64,
    pub stx_size: __u64,
    pub stx_blocks: __u64,
    pub stx_attributes_mask: __u64,
    pub stx_atime: statx_timestamp,
    pub stx_btime: statx_timestamp,
    pub stx_ctime: statx_timestamp,
    pub stx_mtime: statx_timestamp,
    pub stx_rdev_major: __u32,
    pub stx_rdev_minor: __u32,
    pub stx_dev_major: __u32,
    pub stx_dev_minor: __u32,
    pub stx_mnt_id: __u64,
    pub stx_dio_mem_align: __u32,
    pub stx_dio_offset_align: __u32,
    pub stx_subvol: __u64,
    pub stx_atomic_write_unit_min: __u32,
    pub stx_atomic_write_unit_max: __u32,
    pub stx_atomic_write_segments_max: __u32,
    pub __spare1: [__u32; 1usize],
    pub __spare3: [__u64; 9usize],
}

impl Default for statx_timestamp {
    fn default() -> Self {
        statx_timestamp {
            tv_sec: 0,        // 时间戳秒数初始化为 0
            tv_nsec: 0,       // 时间戳纳秒数初始化为 0
            __reserved: 0,    // 保留字段初始化为 0
        }
    }
}

impl Default for statx {
    fn default() -> Self {
        statx {
            stx_mask: 0,
            stx_blksize: 0,
            stx_attributes: 0,
            stx_nlink: 0,
            stx_uid: 0,
            stx_gid: 0,
            stx_mode: 0,
            __spare0: [0; 1],
            stx_ino: 0,
            stx_size: 0,
            stx_blocks: 0,
            stx_attributes_mask: 0,
            stx_atime: statx_timestamp::default(), 
            stx_btime: statx_timestamp::default(),
            stx_ctime: statx_timestamp::default(),
            stx_mtime: statx_timestamp::default(),
            stx_rdev_major: 0,
            stx_rdev_minor: 0,
            stx_dev_major: 0,
            stx_dev_minor: 0,
            stx_mnt_id: 0,
            stx_dio_mem_align: 0,
            stx_dio_offset_align: 0,
            stx_subvol: 0,
            stx_atomic_write_unit_min: 0,
            stx_atomic_write_unit_max: 0,
            stx_atomic_write_segments_max: 0,
            __spare1: [0; 1],
            __spare3: [0; 9],
        }
    }
}