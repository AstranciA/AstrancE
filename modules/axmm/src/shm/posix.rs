//! posix shm

use core::ops::Bound;

use alloc::{
    collections::btree_map::BTreeMap,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use axerrno::{AxError, AxResult, LinuxError};
use axhal::mem::phys_to_virt;
use axsync::Mutex;
use memory_addr::{FrameTracker, MemoryAddr, VirtAddr, PAGE_SIZE_4K};
use page_table_multiarch::PageSize;

use crate::{
    alloc_nframe, backend::frame, shm_get, FrameTrackerRef, ShmError, ShmSegment, IPC_CREAT,
    IPC_EXCL, IPC_PRIVATE,
};

impl ShmSegment {
    pub fn append(&mut self, frames: &[FrameTrackerRef]) {
        for frame in frames {
            self.pages.insert(self.size, frame.clone());
            self.size += frame.size();
        }
    }

    pub fn truncate(&mut self, size: usize) -> AxResult {
        // 函数内会自动检测大小
        self.expand_to(size).and(self.shrink_to(size))
    }

    pub fn shrink_to(&mut self, size: usize) -> AxResult {
        if size >= self.size {
            return Ok(());
        }
        self.pages.split_off(&size);
        self.size = size;
        Ok(())
    }

    pub fn expand_to(&mut self, size: usize) -> AxResult {
        if size <= self.size {
            return Ok(());
        }
        let num_pages: usize = (size - self.size + PAGE_SIZE_4K - 1) / PAGE_SIZE_4K;
        if let Some(frames) = alloc_nframe(num_pages, true) {
            self.append(frames.as_slice());
            self.size = size;
            Ok(())
        } else {
            Err(AxError::NoMemory)
        }
    }

    /// Helper to get the kernel virtual address for a given offset within the SHM segment.
    /// Returns None if the offset is out of bounds or the frame is not found.
    fn get_kva_at_offset(&self, offset: usize) -> Option<VirtAddr> {
        self.pages
            .upper_bound(Bound::Included(&offset))
            .peek_prev()
            .and_then(|(frame_offset, frame)| {
                let in_frame_offset = offset - frame_offset;
                if frame.size() < in_frame_offset {
                    Some(phys_to_virt(frame.pa).wrapping_add(in_frame_offset))
                } else {
                    None
                }
            })
    }

    fn get_slice_at<'a>(&'a self, offset: usize) -> Option<&'a [u8]> {
        warn!("get slice at: 0x{offset:x}");
        self.pages
            .upper_bound(Bound::Included(&offset))
            .peek_prev()
            .and_then(|(frame_offset, frame)| {
                warn!("frame offset : 0x{frame_offset:x}");
                let in_frame_offset = offset - frame_offset;
                if in_frame_offset < frame.size() {
                    unsafe {
                        Some(core::slice::from_raw_parts(
                            phys_to_virt(frame.pa).as_ptr(),
                            frame.size() - in_frame_offset,
                        ))
                    }
                } else {
                    None
                }
            })
    }

    fn get_mut_slice_at<'a>(&'a mut self, offset: usize) -> Option<&'a mut [u8]> {
        self.pages
            .upper_bound_mut(Bound::Included(&offset))
            .peek_prev()
            .and_then(|(frame_offset, frame)| {
                let in_frame_offset = offset - frame_offset;
                if in_frame_offset < frame.size() {
                    unsafe {
                        Some(core::slice::from_raw_parts_mut(
                            phys_to_virt(frame.pa).as_mut_ptr(),
                            frame.size() - in_frame_offset,
                        ))
                    }
                    //Some(&mut frame.as_mut_slice()[in_frame_offset..])
                } else {
                    None
                }
            })
    }

    /// Reads data from the shared memory segment into a buffer.
    ///
    /// # Arguments
    /// * `offset` - The starting offset within the shared memory segment.
    /// * `buf` - The buffer to read data into.
    ///
    /// # Returns
    /// The number of bytes read, or an `AxError` on failure.
    pub fn read_at(&self, offset: usize, buf: &mut [u8]) -> AxResult<usize> {
        // 1. Boundary check: Ensure the offset is within the segment's current size.
        if offset >= self.size {
            return Ok(0); // Offset is beyond the end of the segment, nothing to read.
        }

        // Calculate how many bytes can actually be read.
        let read_len = (self.size - offset).min(buf.len());
        if read_len == 0 {
            return Ok(0); // No bytes to read (either buf is empty or offset is at the very end).
        }

        let mut current_offset = offset;
        let mut bytes_read = 0;

        // Iterate until all requested bytes are read or EOF is reached.
        while bytes_read < read_len {
            let src = self
                .get_slice_at(current_offset)
                .ok_or(AxError::BadAddress)?;

            let bytes_to_copy = src.len().min(read_len - bytes_read);

            buf[bytes_read..bytes_read + bytes_to_copy].copy_from_slice(src);

            // Update counters and offset.
            current_offset += bytes_to_copy;
            bytes_read += bytes_to_copy;
        }

        Ok(bytes_read)
    }

    /// Writes data from a buffer into the shared memory segment.
    ///
    /// # Arguments
    /// * `offset` - The starting offset within the shared memory segment.
    /// * `buf` - The buffer containing data to write.
    ///
    /// # Returns
    /// The number of bytes written, or an `AxError` on failure.
    pub fn write_at(&mut self, offset: usize, buf: &[u8]) -> AxResult<usize> {
        if offset >= self.size {
            if buf.is_empty() {
                return Ok(0);
            } else {
                return Err(AxError::BadAddress); // 或者 AxError::InvalidArgument
            }
        }

        let write_len = (self.size - offset).min(buf.len());
        if write_len == 0 {
            return Ok(0); // 没有字节可写 (要么 buf 为空，要么 offset 已经到共享内存的末尾)
        }

        let mut current_offset = offset;
        let mut bytes_written = 0;

        // Iterate until all requested bytes are written.
        while bytes_written < write_len {
            // 获取共享内存中从 current_offset 开始的可变切片
            // 这个切片代表了当前页的剩余部分，或者直到共享内存末尾
            let dst_part = self.get_mut_slice_at(current_offset).ok_or_else(|| {
                error!(
                    "SHM write error: Failed to get mutable slice for offset {}",
                    current_offset
                );
                AxError::BadAddress // 或者更具体的错误
            })?;

            // 计算可以复制到当前 dst_part 的字节数
            // 它不能超过 dst_part 的长度，也不能超过剩余待写入的字节数
            let bytes_to_copy = dst_part.len().min(write_len - bytes_written);

            // 获取源 buf 中需要复制的部分
            let src_part = &buf[bytes_written..bytes_written + bytes_to_copy];

            // 使用 copy_from_slice 进行复制
            // 这将安全地将 src_part 的数据复制到 dst_part 的开头
            dst_part[..bytes_to_copy].copy_from_slice(src_part);

            // 更新计数器和偏移量
            current_offset += bytes_to_copy;
            bytes_written += bytes_to_copy;
        }

        Ok(bytes_written)
    }
}

pub struct PosixShmManager {
    named_shm_segments: BTreeMap<String, Arc<Mutex<ShmSegment>>>,
    next_shm_id: usize,
}

impl PosixShmManager {
    pub const fn new() -> Self {
        Self {
            named_shm_segments: BTreeMap::new(),
            next_shm_id: 0,
        }
    }

    pub fn read_dir(&self, start: usize, counts: usize) -> Vec<(&String, Arc<Mutex<ShmSegment>>)> {
        self.named_shm_segments
            .iter()
            .skip(start)
            .take(counts)
            .map(|(name, seg)| (name, seg.clone()))
            .collect()
    }

    pub fn get_or_create_shm_segment(
        &mut self,
        path: &str,
        oflag: i32,
        _mode: u32, // Permissions for the shm object, usually handled by VFS layer
    ) -> Result<Arc<Mutex<ShmSegment>>, ShmError> {
        let path_str = path.to_string();

        if (oflag & IPC_CREAT) != 0 {
            // If O_CREAT is set
            if let Some(segment) = self.named_shm_segments.get(&path_str) {
                if (oflag & IPC_EXCL) != 0 {
                    // If O_EXCL is set and it exists, return EEXIST
                    return Err(ShmError::AlreadyExists);
                }
                // Object already exists, return it
                return Ok(Arc::clone(segment));
            } else {
                // Object does not exist, create a new one
                // POSIX SHM objects start with size 0, actual size set by ftruncate
                let new_segment_arc = Arc::new(Mutex::new(ShmSegment::new(
                    self.next_shm_id, // Assign a unique ID
                    IPC_PRIVATE,      // Key is not relevant for POSIX SHM
                    0,                // Initial size is 0
                )));
                self.next_shm_id += 1; // Increment for next ID

                // Store the new segment in the manager
                self.named_shm_segments
                    .insert(path_str, Arc::clone(&new_segment_arc));
                Ok(new_segment_arc)
            }
        } else {
            // O_CREAT is not set, just try to open existing
            if let Some(segment) = self.named_shm_segments.get(&path_str) {
                Ok(Arc::clone(segment))
            } else {
                Err(ShmError::NotFound) // Not found
            }
        }
    }

    // Mark a POSIX SHM object for deletion (shm_unlink)
    pub fn unlink_shm_segment(&mut self, path: &str) -> Result<(), ShmError> {
        let path_str = path.to_string();
        if let Some(segment_arc) = self.named_shm_segments.remove(&path_str) {
            // Mark the underlying ShmSegment for deletion.
            // When its reference count (from VFS nodes) drops to 0, it will be truly freed.
            // This is crucial for POSIX shm_unlink semantics.
            segment_arc.lock().marked_for_deletion = true;
            Ok(())
        } else {
            Err(ShmError::NotFound) // Not found
        }
    }
}
