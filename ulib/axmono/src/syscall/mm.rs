use core::ffi::c_int;

use alloc::sync::Arc;
use axerrno::{LinuxError, LinuxResult};
use axmm::{MmapFlags, MmapPerm};
use axtask::{TaskExtRef, current};
use memory_addr::{va, MemoryAddr};
use page_table_entry::MappingFlags;

use crate::mm::mmap::{MmapIOImpl, MmapResource};

// pub(crate) fn sys_brk(new_heap_top: usize) -> LinuxResult<isize> {
pub fn sys_brk(new_heap_top: usize) -> LinuxResult<isize> {
    let current_task = current();
    let mut aspace = current_task.task_ext().process_data().aspace.lock();
    let old_top = aspace.heap().top();
    if (new_heap_top != 0) {
        // TODO: Validate heap address
        aspace.set_heap_top(va!(new_heap_top));
    }
    // FIXME: return old_top or new_top????
    //Ok(0)
    //Ok(old_top.as_usize() as isize)
    Ok(aspace.heap().top().as_usize() as isize)
}

// pub(crate) fn sys_mprotect(addr: usize, size: usize, prot: usize) -> LinuxResult<isize> {
pub fn sys_mprotect(addr: usize, size: usize, prot: usize) -> LinuxResult<isize> {
    let curr = current();
    let mut aspace = curr.task_ext().process_data().aspace.lock();
    let prot = MappingFlags::from_bits(prot).ok_or(LinuxError::EINVAL)?;
    debug!(
        "mprotect: addr={:#x}, size={:#x}, prot={:?}",
        addr, size, prot
    );
    // TODO: Validate address and size
    aspace.protect(addr.into(), size.align_up_4k(), prot)?;
    Ok(0)
}

/*pub(crate) fn sys_mmap(
    addr: usize,
    len: usize,
    prot: usize,
    flags: usize,
    fd: c_int,
    offset: usize,
) -> LinuxResult<isize> {*/
pub fn sys_mmap(
    addr: usize,
    len: usize,
    prot: usize,
    flags: usize,
    fd: c_int,
    offset: usize,
) -> LinuxResult<isize> {
    let curr = current();
    let mut aspace = curr.task_ext().process_data().aspace.lock();

    if len == 0 {
        return Err(LinuxError::EINVAL);
    }

    let perm = MmapPerm::from_bits_retain(prot);
    let flags = MmapFlags::from_bits_retain(flags);

    debug!("mmap <= addr={:#x}, len={:#x}, prot={:?}, flags={:?}",addr, len, prot, flags);

    // 检查共享类型标志是否有效
    /*
     *if (flags & MmapFlags::MAP_TYPE_MASK).bits() > MmapFlags::MAP_SHARED_VALIDATE.bits() {
     *    return Err(LinuxError::EINVAL);
     *}
     */

    // 处理匿名映射
    let mmap_io = if flags.contains(MmapFlags::MAP_ANONYMOUS) {
        if fd != -1 {
            return Err(LinuxError::EINVAL);
        }
        Arc::new(MmapIOImpl {
            base: 0x0.into(),
            resource: MmapResource::Anonymous,
            file_offset: 0,
            flags,
        })
    } else {
        // 非匿名映射需要有效文件描述符
        if fd == -1 {
            return Err(LinuxError::EBADF);
        }
        Arc::new(MmapIOImpl {
            base: addr.into(),
            resource: MmapResource::file(fd)?,
            file_offset: offset,
            flags,
        })
    };

    // 执行映射
    let populate = flags.contains(MmapFlags::MAP_POPULATE);
    //let populate = true;
    if let Ok(va) = aspace.mmap(addr.into(), len.align_up_4k(), perm, flags, mmap_io, populate) {
        Ok(va.as_usize() as isize)
    } else {
        Err(LinuxError::ENOMEM)
    }
}

pub fn sys_munmap(start: usize, size: usize) -> LinuxResult<isize> {
    let curr = current();
    let mut aspace = curr.task_ext().process_data().aspace.lock();
    let start = start.into();
    let size = size.align_up_4k();
    if aspace.munmap(start, size).is_ok() {
        Ok(0)
    } else {
        Err(LinuxError::EPERM)
    }
}
