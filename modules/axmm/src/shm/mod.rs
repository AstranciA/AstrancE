//! System V Shared Memory (SHM) Management (Simplified, no IPC_PERM)
//!
//! This module handles the allocation, deallocation, and tracking of
//! System V shared memory segments. It manages the physical memory
//! backing these segments and provides interfaces for mapping them
//! into process address spaces.

pub mod posix;

use core::num;

use crate::backend::VmAreaType;
use crate::backend::alloc::{alloc_frame, alloc_nframe};
use crate::backend::frame::FrameTrackerRef; // <--- 使用 FrameTrackerRef
use crate::{AddrSpace, Backend, FrameTrackerMap};
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use axerrno::{AxError, LinuxError};
use axhal::paging::{MappingFlags, PageSize};
use axsync::Mutex; // Assuming spin::Mutex for simplicity in kernel context
use memory_addr::{FrameTracker, VirtAddr, addr_range}; // <--- 引入 PageSize

// KERNEL_PAGE_SIZE should be defined somewhere, e.g., in axhal::paging
const KERNEL_PAGE_SIZE: usize = PageSize::Size4K as usize;

/// Represents a single System V Shared Memory Segment
#[derive(Debug)]
pub struct ShmSegment {
    pub id: usize,                               // Unique SHM ID
    pub key: i32,                                // Key used to create/get the segment
    pub size: usize,                             // Size of the segment in bytes
    pub pages: BTreeMap<usize, FrameTrackerRef>, // Physical pages backing this segment
    pub attach_count: usize,                     // Number of processes attached to this segment
    pub marked_for_deletion: bool,               // New flag for IPC_RMID
}

impl ShmSegment {
    pub fn new(id: usize, key: i32, size: usize) -> Self {
        Self {
            id,
            key,
            size,
            pages: BTreeMap::new(), // Initially empty for POSIX SHM
            attach_count: 0,
            marked_for_deletion: false,
        }
    }
}

pub type ShmManager = Mutex<BTreeMap<usize, Arc<Mutex<ShmSegment>>>>;

// Global state for all SHM segments
// Using a BTreeMap for easy lookup by ID
// We use Arc<Mutex<ShmSegment>> to allow interior mutability for `attach_count`
// and potentially a `marked_for_deletion` flag later, without needing to
// remove and re-insert the segment from the BTreeMap.
pub static SHM_MANAGER: ShmManager = Mutex::new(BTreeMap::new());
static NEXT_SHM_ID: Mutex<usize> = Mutex::new(0); // Simple ID allocator

// IPC Flags (simplified, for internal use)
pub const IPC_PRIVATE: i32 = 0;
pub const IPC_CREAT: i32 = 0o0001000;
pub const IPC_EXCL: i32 = 0o0002000;
// Note: Actual IPC_RMID, IPC_SET, IPC_STAT are for shmctl, not shmget
pub const IPC_RMID: i32 = 0; // Common value for IPC_RMID

#[derive(Debug)]
pub enum ShmError {
    InvalidSize,
    NoMemory,
    AlreadyExists,
    NotFound,
    InvalidId,
    // Add more specific errors as needed, e.g., AlreadyMapped, NotMapped
}

impl From<ShmError> for LinuxError {
    fn from(value: ShmError) -> Self {
        match value {
            ShmError::InvalidSize => LinuxError::EINVAL,
            ShmError::NoMemory => LinuxError::ENOMEM,
            ShmError::AlreadyExists => LinuxError::EEXIST,
            ShmError::NotFound => LinuxError::ENOENT,
            _ => LinuxError::EFAULT, // Generic error for unhandled cases
        }
    }
}

impl From<ShmError> for AxError {
    fn from(value: ShmError) -> Self {
        match value {
            ShmError::InvalidSize => AxError::InvalidInput,
            ShmError::NoMemory => AxError::NoMemory,
            ShmError::AlreadyExists => AxError::AlreadyExists,
            ShmError::NotFound => AxError::NotFound,
            _ => AxError::BadState, // Generic error for unhandled cases
        }
    }
}

/// Creates a new shared memory segment or gets an existing one.
///
/// `key`: IPC key (0 for IPC_PRIVATE)
/// `size`: Size in bytes. Must be page-aligned.
/// `shmflg`: Flags like IPC_CREAT, IPC_EXCL. Permissions are ignored without IpcPerm.
pub fn shm_get(key: i32, size: usize, shmflg: i32) -> Result<Arc<Mutex<ShmSegment>>, ShmError> {
    let mut manager = SHM_MANAGER.lock();

    // 1. Handle IPC_PRIVATE: Always create a new segment
    if key == IPC_PRIVATE {
        return create_new_shm_segment(&mut manager, key, size);
    }

    // 2. Look for existing segment by key
    if let Some(segment) = manager.values().find(|s| s.lock().key == key) {
        // Segment found
        if (shmflg & IPC_CREAT) != 0 && (shmflg & IPC_EXCL) != 0 {
            // IPC_CREAT | IPC_EXCL: segment exists, so error
            return Err(ShmError::AlreadyExists);
        }
        // No permission check without IpcPerm
        Ok(Arc::clone(segment))
    } else {
        // Segment not found
        if (shmflg & IPC_CREAT) != 0 {
            // IPC_CREAT: Create a new one
            create_new_shm_segment(&mut manager, key, size)
        } else {
            // No IPC_CREAT: segment not found, error
            Err(ShmError::NotFound)
        }
    }
}

/// Internal helper to create a new SHM segment.
pub fn create_new_shm_segment(
    manager: &mut BTreeMap<usize, Arc<Mutex<ShmSegment>>>,
    key: i32,
    size: usize,
) -> Result<Arc<Mutex<ShmSegment>>, ShmError> {
    if size == 0 {
        return Err(ShmError::InvalidSize);
    }
    // Round up size to page boundary
    let aligned_size = (size + KERNEL_PAGE_SIZE - 1) & !(KERNEL_PAGE_SIZE - 1);
    let num_pages = aligned_size / KERNEL_PAGE_SIZE;

    // Allocate physical pages using alloc_nframe

    let mut pages = BTreeMap::new();
    let mut offset = 0;
    for frame in alloc_nframe(num_pages, true).ok_or(ShmError::NoMemory)? {
        pages.insert(offset, frame.clone());
        offset += frame.size(); // 假设 FrameTrackerRef 可以被克隆
    }

    let mut next_id = NEXT_SHM_ID.lock();
    let id = *next_id;
    *next_id += 1;

    let new_segment = Arc::new(Mutex::new(ShmSegment {
        id,
        key,
        size: aligned_size,
        pages,
        attach_count: 0,
        marked_for_deletion: false, // Initialize new flag
    }));

    manager.insert(id, Arc::clone(&new_segment));
    Ok(new_segment)
}

/// Attaches a shared memory segment into a process's address space.
///
/// This function now primarily handles the `shmat` system call logic,
/// which involves finding a suitable virtual address and then calling
/// `AddrSpace::shm_mmap` to perform the actual mapping.
pub fn shm_at(
    shm_segment_arc: Arc<Mutex<ShmSegment>>,
    addr: usize,            // Preferred virtual address (0 for kernel to choose)
    shmflg: i32,            // SHM_RDONLY, SHM_REMAP etc.
    aspace: &mut AddrSpace, // Pass the AddrSpace directly
) -> Result<VirtAddr, ShmError> {
    let segment_locked = shm_segment_arc.lock();
    let segment_size = segment_locked.size;
    drop(segment_locked); // Release lock early

    let perm = if (shmflg & 0o10000) != 0 {
        // Assuming SHM_RDONLY is 0o10000
        // Read-only
        crate::aspace::mmap::MmapPerm::PROT_READ
    } else {
        // Read-write
        crate::aspace::mmap::MmapPerm::PROT_READ | crate::aspace::mmap::MmapPerm::PROT_WRITE
    };
    // No other MmapFlags are directly derived from shmflg for now,
    // but you might add MAP_FIXED if addr is non-zero and SHM_REMAP.
    let mmap_flags = if addr != 0 {
        crate::aspace::mmap::MmapFlags::MAP_FIXED
    } else {
        crate::aspace::mmap::MmapFlags::empty()
    };
    // For shm_at, populate should generally be true as it means mapping the existing pages.
    let populate = true;

    // Call the AddrSpace's shm_mmap method
    let vaddr = aspace
        .shm_mmap(
            addr.into(),
            segment_size,
            perm,
            mmap_flags,
            shm_segment_arc.clone(),
            populate,
        )
        .map_err(|_| ShmError::NoMemory)?; // Convert AxError to ShmError

    Ok(vaddr)
}

/// Detaches a shared memory segment from a process's address space.
///
/// This function now primarily handles the `shmdt` system call logic,
/// which involves calling `AddrSpace::munmap` to perform the actual unmapping.
pub fn shm_dt(vaddr: VirtAddr, aspace: &mut AddrSpace) -> Result<(), ShmError> {
    // 1. 在对 `aspace` 进行可变借用之前，先获取所有必要的信息。
    //    需要知道要 unmap 的区域的起始地址和大小，以及它是否是 SHM 区域，
    //    如果是 SHM 区域，还需要拿到对应的 ShmSegment 的 Arc<Mutex>。
    let (area_start_vaddr, area_size, shm_segment_arc_option) = {
        let area = aspace.areas.find(vaddr).ok_or(ShmError::NotFound)?;
        let start = area.start();
        let size = area.size();
        let shm_arc = area.backend().get_shm_segment_arc();
        (start, size, shm_arc)
    };
    // 到这里，`aspace` 的不可变借用已经结束。

    // 2. 执行 munmap 操作。
    //    munmap 内部会处理页表解除映射、MemoryArea 中 FrameTrackerRef 的移除、
    //    以及 attach_count 的递减（如果它是 SHM 区域）。
    //    如果 MemoryArea 变空，munmap 还会将其从 aspace.areas 中移除。
    aspace
        .munmap(vaddr, area_size) // 使用之前获取的 area_size
        .map_err(|_| ShmError::InvalidId)?; // Convert AxError to ShmError

    // 3. 检查是否需要最终删除 ShmSegment。
    //    这个逻辑只在 shm_segment_arc_option 存在时才执行。
    if let Some(segment_arc) = shm_segment_arc_option {
        // 锁定 ShmSegment 以检查其状态
        let mut segment = segment_arc.lock();

        // 只有当 segment 被标记为删除且 attach_count 降为 0 时才执行实际删除
        if segment.marked_for_deletion && segment.attach_count == 0 {
            // 从全局管理器中移除 ShmSegment
            let mut manager = SHM_MANAGER.lock();
            let removed_arc = manager.remove(&segment.id).unwrap(); // 此时 segment 应该还在 manager 中

            // 释放 ShmSegment 内部的 Mutex，然后尝试解包 Arc
            let removed_segment = Arc::try_unwrap(removed_arc)
                .map_err(|_| ShmError::InvalidId)? // 如果这里失败，说明有其他 Arc 引用，不应该发生
                .into_inner(); // 获取内部的 ShmSegment 结构体

            // 物理页的释放：
            // `removed_segment.pages` 是 `Vec<FrameTrackerRef>`，
            // `FrameTrackerRef` 是 `Arc<FrameTrackerImpl>` 的别名。
            // 当 `removed_segment` 被 drop 时，其内部的 `Vec<FrameTrackerRef>` 也会被 drop。
            // 每一个 `FrameTrackerRef` 被 drop 时，如果它是该 `FrameTrackerImpl` 的最后一个 `Arc` 引用，
            // 那么 `FrameTrackerImpl` 的 `Drop` 实现会自动释放其管理的物理页。
            // 所以这里不需要显式的 `for frame_tracker in removed_segment.pages { ... }` 循环。
            // 只需要确保 `removed_segment` 离开了作用域并被 drop 即可。
        }
    }

    Ok(())
}

/// Controls shared memory segments (IPC_RMID, IPC_STAT, IPC_SET).
///
/// `id`: Shared memory segment ID.
/// `cmd`: Command (e.g., IPC_RMID).
/// `buf_ptr`: User-space pointer for `shmid_ds` struct (not used in this simplified version).
pub fn shm_ctl(
    id: usize,
    cmd: i32,
    _buf_ptr: usize, // Placeholder for user buffer pointer
) -> Result<(), ShmError> {
    let mut manager = SHM_MANAGER.lock();

    match cmd {
        IPC_RMID => {
            let segment_arc = manager.get(&id).ok_or(ShmError::NotFound)?.clone();
            let mut segment = segment_arc.lock();

            if segment.attach_count == 0 {
                // Remove from manager and free pages immediately
                let removed_arc = manager.remove(&id).unwrap();
                let removed_segment = Arc::try_unwrap(removed_arc)
                    .map_err(|_| ShmError::InvalidId)? // Should only fail if other Arcs exist
                    .into_inner(); // Get the inner ShmSegment
                // Free physical pages
                for frame_tracker in removed_segment.pages {
                    // frame_tracker will be dropped, which will free the physical page
                }
            } else {
                // Mark for deletion
                segment.marked_for_deletion = true;
            }
            Ok(())
        }
        // IPC_STAT, IPC_SET would involve copying data to/from user space and
        // modifying segment properties. Not implemented in this simplified version.
        _ => Err(ShmError::InvalidId), // Unknown or unsupported command
    }
}

// Helper to get ShmSegment Arc from Backend (for munmap)
impl Backend {
    pub fn get_shm_segment_arc(&self) -> Option<Arc<Mutex<ShmSegment>>> {
        if let Backend::Alloc { va_type, .. } = self {
            if let VmAreaType::Shm(shm_segment_arc) = va_type {
                return Some(shm_segment_arc.clone());
            }
        }
        None
    }
}
