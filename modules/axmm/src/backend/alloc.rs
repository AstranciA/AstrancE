use alloc::sync::Arc;
use alloc::vec::Vec;
use axalloc::global_allocator;
use axhal::mem::{phys_to_virt, virt_to_phys};
use axhal::paging::{MappingFlags, PageSize, PageTable};
use bitflags::Flags;
use memory_addr::{FrameTracker, MemoryAddr, PAGE_SIZE_4K, PageIter4K, PhysAddr, VirtAddr};

use crate::{AddrSpace, MmapFlags};

use super::frame::{FrameTrackerImpl, FrameTrackerMap, FrameTrackerRef};
use super::{Backend, VmAreaType};

pub(crate) fn alloc_nframe(num_pages: usize, zeroed: bool) -> Option<Vec<FrameTrackerRef>> {
    let mut frames = Vec::with_capacity(num_pages);
    for _ in 0..num_pages {
        if let Some(frame) = alloc_frame(zeroed) {
            frames.push(frame);
        } else {
            return None;
        }
    }
    Some(frames)
}

/// TODO: paddr???? what happends if page table is not kernel's?
/// WARN: it's not the real physical addr unless it is undering the kernel's virtual memory space
/*
 *fn alloc_frame(zeroed: bool) -> Option<PhysAddr> {
 *    let vaddr = VirtAddr::from(global_allocator().alloc_pages(1, PAGE_SIZE_4K).ok()?);
 *    if zeroed {
 *        unsafe { core::ptr::write_bytes(vaddr.as_mut_ptr(), 0, PAGE_SIZE_4K) };
 *    }
 *    // pa ???
 *    let paddr = virt_to_phys(vaddr);
 *    Some(paddr)
 *}
 */
pub(crate) fn alloc_frame(zeroed: bool) -> Option<FrameTrackerRef> {
    let vaddr = VirtAddr::from(global_allocator().alloc_pages(1, PAGE_SIZE_4K).ok()?);
    if zeroed {
        unsafe { core::ptr::write_bytes(vaddr.as_mut_ptr(), 0, PAGE_SIZE_4K) };
    }
    let paddr = virt_to_phys(vaddr);
    Some(Arc::new(FrameTrackerImpl::new(paddr)))
}

fn alloc_frame2(zeroed: bool) -> Option<VirtAddr> {
    let vaddr = VirtAddr::from(global_allocator().alloc_pages(1, PAGE_SIZE_4K).ok()?);
    if zeroed {
        unsafe { core::ptr::write_bytes(vaddr.as_mut_ptr(), 0, PAGE_SIZE_4K) };
    }
    Some(vaddr)
}

pub fn dealloc_frame(frame: PhysAddr) {
    let vaddr = phys_to_virt(frame);
    global_allocator().dealloc_pages(vaddr.as_usize(), 1);
}

impl Backend {
    /// Creates a new allocation mapping backend.
    pub const fn new_alloc(populate: bool) -> Self {
        Self::Alloc {
            populate,
            va_type: VmAreaType::Normal,
        }
    }

    /// Creates a new allocation mapping backend.
    pub const fn new(populate: bool, va_type: VmAreaType) -> Self {
        Self::Alloc { populate, va_type }
    }

    pub(crate) fn map_alloc(
        start: VirtAddr,
        size: usize,
        flags: MappingFlags,
        pt: &mut PageTable,
        va_type: VmAreaType,
        populate: bool,
    ) -> Result<FrameTrackerMap, ()> {
        debug!(
            "map_alloc: [{:#x}, {:#x}) {:?} (populate={})",
            start,
            start + size,
            flags,
            populate
        );
        let mut frame_tracker_map = FrameTrackerMap::new();
        if populate {
            // allocate all possible physical frames for populated mapping.
            for addr in PageIter4K::new(start, start + size).unwrap() {
                if let Some(frame) = alloc_frame(true) {
                    frame_tracker_map.insert(addr, frame.clone());
                    if let Ok(tlb) = pt.map(addr, frame.pa, PageSize::Size4K, flags) {
                        tlb.ignore(); // TLB flush on map is unnecessary, as there are no outdated mappings.
                    } else {
                        return Err(());
                    }
                }
            }
        } else {
            // create mapping entries on demand later in `handle_page_fault_alloc`.
        }
        Ok(frame_tracker_map)
    }

    /// unmap pages from page table,
    /// but not deallocate pages which should be deallocated by frame tracker.
    pub(crate) fn unmap_alloc(
        start: VirtAddr,
        size: usize,
        pt: &mut PageTable,
        _va_type: VmAreaType, //TODO
        _populate: bool,
    ) -> bool {
        trace!("unmap_alloc: [{:#x}, {:#x})", start, start + size);
        for addr in PageIter4K::new(start, (start + size).align_up_4k()).unwrap() {
            if let Ok((frame, page_size, tlb)) = pt.unmap(addr) {
                // Deallocate the physical frame if there is a mapping in the
                // page table.
                if page_size.is_huge() {
                    return false;
                }
                tlb.flush();
            } else {
                // Deallocation is needn't if the page is not mapped.
            }
        }
        true
    }
    pub(super) fn handle_page_fault_cow(
        vaddr: VirtAddr,
        orig_flags: MappingFlags,
        aspace: &mut AddrSpace,
    ) -> bool {
        if !orig_flags.contains(MappingFlags::WRITE) {
            debug!("Trying to COW but area not writable: {vaddr:x?}");
            return false;
        }

        if let Ok((_, pte_flag, _)) = aspace.pt.query(vaddr) {
            if !pte_flag.contains(MappingFlags::COW) {
                debug!("Trying to COW but not marked as COW: {vaddr:x?}");
                return false;
            }
        } else {
            debug!("vaddr not found in page table: {vaddr:x?}");
            return false;
        }

        trace!("handle_page_fault_cow: COW page fault at {:#x}", vaddr);
        let origin = if let Some(origin) = aspace.find_frame(vaddr.align_down_4k()) {
            origin
        } else {
            debug!("frame not found in aspace");
            return false;
        };
        let count = Arc::strong_count(&origin) - 1; // exclude origin self
        let origin_pa = origin.pa;

        // if origin frame is only be hold in `aspace`, we can reuse it.
        if count == 1 {
            trace!("COW reusing frame {:#x}", origin_pa);
            return aspace
                .page_table()
                .remap(vaddr, origin_pa, orig_flags)
                .map(|(_, tlb)| tlb.flush())
                .is_ok();
        }

        // else clone it.
        if let Some(frame) = alloc_frame(false) {
            // Allocate a physical frame lazily, map it to the fault address,
            // and copy the original content to the new frame.
            // `vaddr` does not need to be aligned. It will be automatically
            // aligned during `pt.map` regardless of the page size.

            // Copy the original content to the new frame.
            trace!(
                "Copying {:?} bytes from {:#x} to new frame {:#x}",
                PageSize::Size4K,
                vaddr.align_down_4k(),
                frame.pa
            );
            unsafe {
                core::ptr::copy_nonoverlapping(
                    vaddr.align_down_4k().as_ptr(),
                    phys_to_virt(frame.pa).as_mut_ptr(),
                    PageSize::Size4K.into(),
                )
            };
            return aspace.remap(vaddr, frame, orig_flags);

            /*
             *let result = pt
             *    .remap(
             *        vaddr,
             *        frame.pa,
             *        (orig_flags - MappingFlags::COW) | MappingFlags::WRITE,
             *    )
             *    .map(|(_, tlb)| tlb.flush());
             *return result.and_then(|_| {
             *        // TODO: Remap frame tracker here
             *        let vaddr = vaddr.align_down_4k();
             *        let origin = aspace.find_frame(vaddr).unwrap();
             *        error!("Trying to remap frame tracker {:?} from {:?} to {:?}.", vaddr, origin, frame);
             *        error!("count: of {origin:?} {}", Arc::strong_count(&origin));
             *        error!("count: of {origin:?} {}", Arc::strong_count(&origin));
             *        let origin = aspace.find_frame(vaddr).unwrap();
             *        error!("count: of {origin:?} {}", Arc::strong_count(&origin));
             *        Ok(())
             *    }).is_ok();
             */
        }
        false
    }

    pub(crate) fn handle_page_fault_alloc(
        vaddr: VirtAddr,
        va_type: VmAreaType,
        orig_flags: MappingFlags,
        //pt: &mut PageTable,
        aspace: &mut AddrSpace,
        populate: bool,
    ) -> bool {
        if populate {
            #[cfg(not(feature = "COW"))]
            return false; // Populated mappings should not trigger page faults.
            // should be COW page faults
            // TODO: update frame ref in addr space
            #[cfg(feature = "COW")]
            return match va_type {
                VmAreaType::Normal | VmAreaType::Mmap(_) => {
                    Self::handle_page_fault_cow(vaddr, orig_flags, aspace)
                }
                _ => false,
            };
        }
        match va_type {
            VmAreaType::Normal => {
                if let Some(frame) = alloc_frame(true) {
                    // Allocate a physical frame lazily and map it to the fault address.
                    // `vaddr` does not need to be aligned. It will be automatically
                    // aligned during `pt.map` regardless of the page size.
                    return aspace
                        .page_table()
                        .map(vaddr, frame.pa, PageSize::Size4K, orig_flags)
                        .map(|tlb| tlb.flush())
                        .and_then(|_| {
                            aspace.areas.insert_frame(vaddr, frame.clone());
                            Ok(())
                        })
                        .is_ok();
                }
                return false;
            }
            VmAreaType::Mmap(mmio) => {
                let flags = orig_flags;

                if !flags.contains(MappingFlags::DEVICE) {
                    return false;
                };

                if mmio.flags().contains(MmapFlags::MAP_ANONYMOUS) {
                    if let Some(frame) = alloc_frame(true) {
                        // Allocate a physical frame lazily and map it to the fault address.
                        // `vaddr` does not need to be aligned. It will be automatically
                        // aligned during `pt.map` regardless of the page size.
                        return aspace
                            .page_table()
                            .map(vaddr, frame.pa, PageSize::Size4K, orig_flags)
                            .map(|tlb| tlb.flush())
                            .and_then(|_| {
                                aspace.areas.insert_frame(vaddr, frame.clone());
                                Ok(())
                            })
                            .is_ok();
                    }
                    return false;
                }
                return aspace
                    .populate_mmap(mmio, vaddr, PageSize::Size4K, flags)
                    .is_ok();

                /*
                 *if flags.contains(MappingFlags::COW) {
                 *    return Self::handle_page_fault_cow(vaddr, orig_flags, aspace);
                 *}
                 */
            }
            VmAreaType::Shm(shm_segment) => {
                // For SHM, the physical frames are *already* allocated and stored in ShmSegment.
                // We just need to map the correct one.
                let shm_segment_locked = shm_segment.lock();
                let page_idx = (vaddr.align_down_4k() - aspace.areas.find(vaddr).unwrap().start())
                    / (PageSize::Size4K as usize);

                if page_idx >= shm_segment_locked.pages.len() {
                    error!(
                        "SHM page fault: index out of bounds for segment pages. vaddr: {:?}, page_idx: {}",
                        vaddr, page_idx
                    );
                    return false;
                }

                let frame = shm_segment_locked.pages[page_idx].clone(); // Get the pre-allocated frame
                drop(shm_segment_locked);

                // Map the physical frame into the process's page table
                aspace
                    .page_table()
                    .map(vaddr, frame.pa, PageSize::Size4K, orig_flags)
                    .map(|tlb| tlb.flush())
                    .and_then(|_| {
                        aspace.areas.insert_frame(vaddr, frame.clone());
                        Ok(())
                    })
                    .is_ok()
            }
            VmAreaType::Elf => todo!(),
            VmAreaType::Heap => todo!(),
            VmAreaType::Stack => todo!(),
        }
    }
}
