use alloc::sync::Arc;
use axerrno::{AxError, AxResult, ax_err};
use axhal::{
    mem::{MemoryAddr, phys_to_virt},
    paging::{MappingFlags, PageSize},
};
use axsync::Mutex;
use bitflags::bitflags;
use memory_addr::{PageIter4K, VirtAddr, addr_range, va};
use memory_set::MemoryArea; // <--- 引入 Mutex

use crate::{
    AddrSpace,
    Backend,
    backend::{VmAreaType, alloc::alloc_frame},
    mapping_err_to_ax_err,
    shm::ShmSegment, // <--- 引入 ShmSegment
};

const MMAP_END: VirtAddr = va!(0x4000_0000);

bitflags! {
    #[derive(Default, Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct MmapFlags: usize {
        // Sharing types (must choose one and only one of these)
        const MAP_SHARED = 0x01;
        const MAP_PRIVATE = 0x02;
        //const MAP_SHARED_VALIDATE = 0x03;
        //const MAP_TYPE_MASK = 0x0f;
        // Other flags
        const MAP_FIXED = 0x10;
        const MAP_FIXED_NOREPLACE = 0x100000;
        const MAP_ANONYMOUS = 0x20;
        //const MAP_NORESERVE = 0x04000;
        const MAP_POPULATE = 0x08000;
        //const MAP_LOCKED = 0x02000;
        //const MAP_STACK = 0x20000;
        //const MAP_HUGETLB = 0x40000;
    }
}

bitflags! {
    // Defined in <bits/mman-linux.h>
    // NOTE: Zero bit flag is discouraged. See https://docs.rs/bitflags/latest/bitflags/#zero-bit-flags
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct MmapPerm: usize {
        /// Page can be read.
        const PROT_READ = 0x1;
        /// Page can be written.
        const PROT_WRITE = 0x2;
        /// Page can be executed.
        const PROT_EXEC = 0x4;
    }
}

impl From<MmapPerm> for MappingFlags {
    fn from(prot: MmapPerm) -> Self {
        let mut ret = Self::USER;
        if prot.contains(MmapPerm::PROT_READ) {
            ret |= Self::READ;
        }
        if prot.contains(MmapPerm::PROT_WRITE) {
            ret |= Self::WRITE;
        }
        if prot.contains(MmapPerm::PROT_EXEC) {
            ret |= Self::EXECUTE;
        }
        ret
    }
}

pub trait MmapIO: Send + Sync {
    // require inner mutability
    fn set_base(&self, base: VirtAddr);
    fn read(&self, va: usize, buf: &mut [u8]) -> AxResult<usize>;
    fn write(&self, va: usize, data: &[u8]) -> AxResult<usize>;
    fn flags(&self) -> MmapFlags;
}

/// TODO: 限制mmap大小
impl AddrSpace {
    // Existing mmap function for MmapIO
    pub fn mmap(
        &mut self,
        start: VirtAddr,
        size: usize,
        perm: MmapPerm,
        flags: MmapFlags,
        mmap_io: Arc<dyn MmapIO>,
        populate: bool,
    ) -> AxResult<VirtAddr> {
        debug_assert!(start.is_aligned_4k());
        debug_assert!(size % 4096 == 0);

        let start = self.find_and_prepare_vaddr(start, size, flags)?;

        let mut map_flags: MappingFlags = perm.into();
        map_flags = map_flags | MappingFlags::DEVICE; // Assuming MmapIO is device-like
        debug!(
            "mmap at: [{:#x}, {:#x}), {map_flags:?}",
            start,
            start + size
        );
        mmap_io.set_base(start);

        let area = MemoryArea::new_mmap(
            start,
            size.align_up_4k(),
            None,
            map_flags,
            Backend::new(populate, VmAreaType::Mmap(mmap_io.clone())),
        );

        if populate {
            for page in PageIter4K::new(area.start(), area.end()).ok_or(AxError::BadAddress)? {
                self.populate_mmap(mmap_io.clone(), page, PageSize::Size4K, map_flags)?;
            }
        }
        self.areas
            .insert(area, false)
            .map_err(mapping_err_to_ax_err)?;
        Ok(start)
    }

    // New function for SHM mmap
    pub fn shm_mmap(
        &mut self,
        start: VirtAddr,
        size: usize,
        perm: MmapPerm,
        flags: MmapFlags,
        shm_segment: Arc<Mutex<ShmSegment>>, // Pass the ShmSegment directly
        populate: bool,
    ) -> AxResult<VirtAddr> {
        debug_assert!(start.is_aligned_4k());
        debug_assert!(size % 4096 == 0);

        let start = self.find_and_prepare_vaddr(start, size, flags)?;

        let map_flags: MappingFlags = perm.into();
        debug!(
            "shm_mmap at: [{:#x}, {:#x}), {map_flags:?}",
            start,
            start + size
        );

        let area = MemoryArea::new_mmap(
            start,
            size.align_up_4k(),
            None,
            map_flags,
            Backend::new(populate, VmAreaType::Shm(shm_segment.clone())), // Use Shm VmAreaType
        );

        self.areas
            .insert(area, false)
            .map_err(mapping_err_to_ax_err)?;

        // For SHM, `populate` means mapping the existing physical pages.
        // The `shm_segment` already holds the `FrameTrackerRef`s.
        if populate {
            self.populate_shm(shm_segment.clone(), start, size, map_flags).inspect_err(|e|warn!("{e:?}"))?;
        }

        // Increment attach_count when successfully mapped
        shm_segment.lock().attach_count += 1;

        Ok(start)
    }

    // Helper to find and prepare virtual address
    fn find_and_prepare_vaddr(
        &mut self,
        start: VirtAddr,
        size: usize,
        flags: MmapFlags,
    ) -> AxResult<VirtAddr> {
        let actual_start = if flags.contains(MmapFlags::MAP_FIXED) {
            // TODO: check if it's USER
            self.unmap(start, size)?;
            start
        } else if flags.contains(MmapFlags::MAP_FIXED_NOREPLACE) {
            start
        } else {
            let search_start = if start.as_usize() == 0 {
                va!(0x1000)
            } else {
                start
            };
            #[cfg(feature = "heap")]
            {
                // should below heap
                let heap_start = self
                    .heap
                    .as_ref()
                    .map(|h| h.base())
                    .unwrap_or(MMAP_END)
                    .into();
                self.find_free_area(
                    search_start.into(),
                    size,
                    addr_range!(self.base().as_usize()..heap_start),
                )
                .expect("Cannot find free area for mmap")
            }
            #[cfg(not(feature = "heap"))]
            {
                self.find_free_area(
                    start.into(),
                    size,
                    addr_range!(self.base().as_usize()..MMAP_END.into()),
                )
                .expect("Cannot find free area for mmap")
            }
        };
        Ok(actual_start)
    }

    pub fn populate_mmap(
        &mut self,
        mmio: Arc<dyn MmapIO>,
        vaddr: VirtAddr,
        size: PageSize,
        flags: MappingFlags,
    ) -> AxResult {
        let vaddr = vaddr.align_down_4k();
        //warn!("areas: {:#?}", self.areas);
        if let Some(frame) = alloc_frame(true) {
            let area = self.areas.find_mut(vaddr).ok_or(AxError::BadAddress)?;
            debug!(
                "{:?}->{:?}, area:{:?}..{:?}, flags: {:?}",
                vaddr,
                frame.pa,
                area.start(),
                area.end(),
                flags
            );

            let dst = unsafe {
                core::slice::from_raw_parts_mut(phys_to_virt(frame.pa).as_mut_ptr(), size.into())
            };
            mmio.read(vaddr.as_usize(), dst)?;
            area.insert_frame(vaddr, frame.clone());

            self.page_table()
                .map(vaddr, frame.pa, size, flags)
                .inspect_err(|e| warn!("Error mapping mmap: {:?}", e))
                .map(|tlb| tlb.flush())
                .map_err(|_| AxError::BadAddress)?;

            Ok(())
        } else {
            Err(AxError::NoMemory)
        }
    }

    // New function to populate SHM pages
    pub fn populate_shm(
        &mut self,
        shm_segment: Arc<Mutex<ShmSegment>>,
        start_vaddr: VirtAddr,
        total_size: usize,
        flags: MappingFlags,
    ) -> AxResult {
        let shm_segment_locked = shm_segment.lock();
        let segment_pages = &shm_segment_locked.pages;
        let num_pages = total_size / PageSize::Size4K as usize;

        if num_pages > segment_pages.len() {
            return ax_err!(InvalidInput, "SHM segment too small for requested size");
        }

        let area = self
            .areas
            .find_mut(start_vaddr)
            .ok_or(AxError::BadAddress)?;

        for i in 0..num_pages {
            let vaddr = start_vaddr + i * PageSize::Size4K as usize;
            let frame = segment_pages[i].clone(); // Get the pre-allocated frame from ShmSegment

            debug!(
                "Populating SHM: {:?}->{:?}, area:{:?}..{:?}, flags: {:?}",
                vaddr,
                frame.pa,
                area.start(),
                area.end(),
                flags
            );

            area.insert_frame(vaddr, frame.clone()); // Add to MemoryArea's frame tracking

            self.pt
                .map(vaddr, frame.pa, PageSize::Size4K, flags)
                .inspect_err(|e| warn!("Error mapping SHM: {:?}", e))
                .map(|tlb| tlb.flush())
                .map_err(|_| AxError::BadAddress)?;
        }
        Ok(())
    }

    pub fn munmap(&mut self, start: VirtAddr, size: usize) -> AxResult {
        // TODO: is it correct?
        let size = size.align_up_4k();
        let end = start + size;
        let area = match self.areas.find_mut(start) {
            Some(area) => area,
            None => return Ok(()),
        };
        if area.end() < end {
            error!(
                "[{:#x}, {:#x}) out of range [{:#x}, {:#x})",
                start,
                end,
                area.start(),
                area.end()
            );
            return ax_err!(BadAddress, "munmap end out of range");
        }

        let is_shm = if let Backend::Alloc { va_type, .. } = area.backend() {
            if let VmAreaType::Shm(shm_segment) = va_type {
                // Decrement attach_count when unmapped
                shm_segment.lock().attach_count -= 1;
                true
            } else {
                false
            }
        } else {
            false
        };

        area.unmap_frames(start, size, &mut self.pt).unwrap();
        let is_empty = area.frames_count() == 0;
        let area_start = area.start();
        if is_empty {
            self.unmap_area(area_start);
        }

        Ok(())
    }
}
