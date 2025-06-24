use core::ffi::{CStr, c_char, c_int, c_long};

use axruntime::SYSINFO;

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
        error!("sys_uname <= {:?}", SYSINFO.sysname.as_bytes());
        str_to_cstr(SYSINFO.nodename, (*buf).nodename.as_mut_ptr());
        str_to_cstr(SYSINFO.release, (*buf).release.as_mut_ptr());
        str_to_cstr(SYSINFO.version, (*buf).version.as_mut_ptr());
        str_to_cstr(SYSINFO.machine, (*buf).machine.as_mut_ptr());
    }
    syscall_body!(sys_uname, { Ok(0) })
}
