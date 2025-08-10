use core::ffi::{CStr, c_char, c_int, c_long, c_ulong, c_ushort};
use axruntime::SYSINFO;
use core::ptr;
use crate::{ctypes, utils::str_to_cstr};

const PAGE_SIZE_4K: usize = 4096;

/// Return system configuration infomation
///
/// Notice: currently only support what unikraft covers
pub fn sys_sysconf(name: c_int) -> c_long {
    debug!("sys_sysconf <= {}", name);

    #[cfg(feature = "alloc")]
    let (phys_pages, avail_pages) = {
        let alloc = axalloc::global_allocator();
        let avail_pages = alloc.available_pages();
        (alloc.used_pages() + avail_pages, avail_pages)
    };

    #[cfg(not(feature = "alloc"))]
    let (phys_pages, avail_pages) = {
        let mem_size = axconfig::plat::PHYS_MEMORY_SIZE;
        (mem_size / PAGE_SIZE_4K, mem_size / PAGE_SIZE_4K) // TODO
    };

    syscall_body!(sys_sysconf, {
        match name as u32 {
            // Page size
            ctypes::_SC_PAGE_SIZE => Ok(PAGE_SIZE_4K),
            // Number of processors in use
            ctypes::_SC_NPROCESSORS_ONLN => Ok(axconfig::SMP),
            // Total physical pages
            ctypes::_SC_PHYS_PAGES => Ok(phys_pages),
            // Avaliable physical pages
            ctypes::_SC_AVPHYS_PAGES => Ok(avail_pages),
            // Maximum number of files per process
            #[cfg(feature = "fd")]
            ctypes::_SC_OPEN_MAX => Ok(super::fd_ops::AX_FILE_LIMIT),
            _ => Ok(0),
        }
    })
}

#[repr(C)]
#[derive(Debug)]
pub struct UtsName {
    pub sysname: [c_char; 65],
    pub nodename: [c_char; 65],
    pub release: [c_char; 65],
    pub version: [c_char; 65],
    pub machine: [c_char; 65],
    pub domainname: [c_char; 65],
}

pub fn sys_uname(buf: *mut UtsName) -> c_long {
    let dst = unsafe { core::slice::from_raw_parts(buf as *const c_char, 17) };
    unsafe {
        str_to_cstr(SYSINFO.sysname, (*buf).sysname.as_mut_ptr());
        str_to_cstr(SYSINFO.sysname, (*buf).domainname.as_mut_ptr());
        str_to_cstr(SYSINFO.nodename, (*buf).nodename.as_mut_ptr());
        str_to_cstr(SYSINFO.release, (*buf).release.as_mut_ptr());
        str_to_cstr(SYSINFO.version, (*buf).version.as_mut_ptr());
        str_to_cstr(SYSINFO.machine, (*buf).machine.as_mut_ptr());
    }
    syscall_body!(sys_uname, { Ok(0) })
}

#[repr(C)]
#[derive(Debug)]
pub struct SysInfo {
    pub uptime: c_long,
    pub loads: [c_long; 3],
    pub freeram: c_ulong,
    pub sharedram: c_ulong,
    pub bufferram: c_ulong,
    pub totalswaps: c_ulong,
    pub freeswaps: c_ulong,
    pub procs: c_ushort,
    _pad: [c_char; 22],
}

pub fn sys_sysinfo(buf: *mut SysInfo) -> c_long {
    // uptime: 假设 axtime::uptime_secs() 返回秒数
    use axhal::time::{monotonic_time_nanos, NANOS_PER_SEC};
    let uptime = monotonic_time_nanos() / NANOS_PER_SEC;

    // load average: TODO - 需要调度器支持，这里先全 0
    let loads = [0i64, 0i64, 0i64];

    // 空闲内存（标记 FREE 的区域总和）
    use axhal::mem::{memory_regions, MemRegionFlags};
    let freeram: u64 = memory_regions()
        .filter(|r| r.flags.contains(MemRegionFlags::FREE))
        .map(|r| r.size as u64)
        .sum();

    // 共享内存/缓冲区：TODO 目前无实现
    let sharedram = 0u64;
    let bufferram = 0u64;

    // swap 空间：TODO 目前无实现
    let totalswap = 0u64;
    let freeswap = 0u64;

    // 进程数（任务数）TODO
    let procs = 0 as u16;

    unsafe {
        ptr::write(buf, SysInfo {
            uptime: uptime.try_into().unwrap(),
            loads,
            freeram,
            sharedram,
            bufferram,
            totalswaps: totalswap.try_into().unwrap(),
            freeswaps: freeswap.try_into().unwrap(),
            procs,
            _pad: [0; 22], // 填充字节初始化为 0
        });
    }
    syscall_body!(sys_sysinfo, Ok(0))
}
