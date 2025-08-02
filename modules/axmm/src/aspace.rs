use axerrno::{AxError, AxResult, ax_err};
use axhal::mem::phys_to_virt;
use axhal::paging::{MappingFlags, PageTable, PagingError};
use core::fmt;
use memory_addr::{
    MemoryAddr, PAGE_SIZE_4K, PageIter4K, PhysAddr, VirtAddr, VirtAddrRange, is_aligned_4k,
};
use memory_set::{MappingBackend, MemoryArea, MemorySet};

#[cfg(feature = "mmap")]
pub mod mmap;

use crate::backend::Backend;
use crate::backend::frame::FrameTrackerRef;
use crate::heap::HeapSpace;
use crate::mapping_err_to_ax_err;

/// The virtual memory address space.
pub struct AddrSpace {
    va_range: VirtAddrRange,
    pub areas: MemorySet<Backend>,
    pub(crate) pt: PageTable,
    #[cfg(feature = "heap")]
    pub(crate) heap: Option<HeapSpace>,
}

impl AddrSpace {
    /// Returns the address space base.
    pub const fn base(&self) -> VirtAddr {
        self.va_range.start
    }

    /// Returns the address space end.
    pub const fn end(&self) -> VirtAddr {
        self.va_range.end
    }

    /// Returns the address space size.
    pub fn size(&self) -> usize {
        self.va_range.size()
    }

    /// Returns the reference to the inner page table.
    pub const fn page_table(&mut self) -> &mut PageTable {
        &mut self.pt
    }

    /// Returns the root physical address of the inner page table.
    pub const fn page_table_root(&self) -> PhysAddr {
        self.pt.root_paddr()
    }

    /// Checks if the address space contains the given address range.
    pub fn contains_range(&self, start: VirtAddr, size: usize) -> bool {
        self.va_range
            .contains_range(VirtAddrRange::from_start_size(start, size))
    }

    /// Creates a new empty address space.
    pub fn new_empty(base: VirtAddr, size: usize) -> AxResult<Self> {
        Ok(Self {
            va_range: VirtAddrRange::from_start_size(base, size),
            areas: MemorySet::new(),
            pt: PageTable::try_new().map_err(|_| AxError::NoMemory)?,
            #[cfg(feature = "heap")]
            heap: None,
        })
    }

    pub fn new_empty_like(other: &AddrSpace) -> AxResult<Self> {
        Ok(Self {
            va_range: other.va_range,
            areas: MemorySet::new(),
            pt: PageTable::try_new().map_err(|_| AxError::NoMemory)?,
            #[cfg(feature = "heap")]
            heap: None,
        })
    }

    pub fn find_frame(&self, vaddr: VirtAddr) -> Option<FrameTrackerRef> {
        self.areas.find_frame(vaddr)
    }

    /// Remap a vaddr to a new frame.pub fn remap_frame(&mut self, vaddr:
    /// B::Addr, new_frame: B::FrameTrackerImpl) {
    pub fn remap(
        &mut self,
        vaddr: VirtAddr,
        new_frame: <Backend as MappingBackend>::FrameTrackerRef,
        new_flags: MappingFlags,
    ) -> bool {
        //self.areas.remap_frame(vaddr, new_frame);
        self.pt
            .remap(vaddr, new_frame.pa, new_flags)
            .map(|(_, tlb)| tlb.flush())
            .is_ok()
            .then(|| {
                let vaddr = vaddr.align_down_4k();

                trace!(
                    "Trying to remap frame tracker {:?} to {:?}.",
                    vaddr, new_frame
                );
                self.areas.remap_frame(vaddr, new_frame);
                true
            })
            .unwrap_or(false)
    }

    /// Copies page table mappings from another address space.
    ///
    /// It copies the page table entries only rather than the memory regions,
    /// usually used to copy a portion of the kernel space mapping to the
    /// user space.
    ///
    /// Note that on dropping, the copied PTEs will also be cleared, which could
    /// taint the original page table. For workaround, you can use
    /// [`AddrSpace::clear_mappings`].
    ///
    /// Returns an error if allow_overlap is false and the two address spaces overlap.
    pub fn copy_mappings_from(&mut self, other: &AddrSpace, allow_overlap: bool) -> AxResult {
        if !allow_overlap && self.va_range.overlaps(other.va_range) {
            return ax_err!(InvalidInput, "address space overlap");
        }
        self.pt.copy_from(&other.pt, other.base(), other.size());
        Ok(())
    }

    /// Clears the page table mappings in the given address range.
    ///
    /// This should be used in pair with [`AddrSpace::copy_mappings_from`].
    pub fn clear_mappings(&mut self, range: VirtAddrRange) {
        self.pt.clear_copy_range(range.start, range.size());
    }

    pub(crate) fn validate_region(&self, start: VirtAddr, size: usize) -> AxResult {
        if !self.contains_range(start, size) {
            return ax_err!(InvalidInput, "address out of range");
        }
        if !start.is_aligned_4k() || !is_aligned_4k(size) {
            warn!("{start:?}, {size:?}");
            return ax_err!(InvalidInput, "address not aligned");
        }
        Ok(())
    }

    /// Finds a free area that can accommodate the given size.
    ///
    /// The search starts from the given hint address, and the area should be within the given limit range.
    ///
    /// Returns the start address of the free area. Returns None if no such area is found.
    pub fn find_free_area(
        &self,
        hint: VirtAddr,
        size: usize,
        limit: VirtAddrRange,
    ) -> Option<VirtAddr> {
        self.areas.find_free_area(hint, size, limit)
    }

    /// Add a new linear mapping.
    ///
    /// See [`Backend`] for more details about the mapping backends.
    ///
    /// The `flags` parameter indicates the mapping permissions and attributes.
    ///
    /// Returns an error if the address range is out of the address space or not
    /// aligned.
    pub fn map_linear(
        &mut self,
        start_vaddr: VirtAddr,
        start_paddr: PhysAddr,
        size: usize,
        flags: MappingFlags,
    ) -> AxResult {
        self.validate_region(start_vaddr, size)?;
        if !start_paddr.is_aligned_4k() {
            return ax_err!(InvalidInput, "address not aligned");
        }

        let offset = start_vaddr.as_usize() - start_paddr.as_usize();
        let area = MemoryArea::new(start_vaddr, size, None, flags, Backend::new_linear(offset));
        self.areas
            .map(area, &mut self.pt, false, None)
            .map_err(mapping_err_to_ax_err)?;
        Ok(())
    }

    /// Add a new allocation mapping.
    ///
    /// See [`Backend`] for more details about the mapping backends.
    ///
    /// The `flags` parameter indicates the mapping permissions and attributes.
    ///
    /// Returns an error if the address range is out of the address space or not
    /// aligned.
    pub fn map_alloc(
        &mut self,
        start: VirtAddr,
        size: usize,
        flags: MappingFlags,
        populate: bool,
    ) -> AxResult {
        self.validate_region(start, size)?;

        let area = MemoryArea::new(start, size, None, flags, Backend::new_alloc(populate));
        self.areas
            .map(area, &mut self.pt, false, None)
            .map_err(mapping_err_to_ax_err)?;
        Ok(())
    }

    /// Populates the area with physical frames, returning false if the area
    /// contains unmapped area.
    pub fn populate_area(&mut self, mut start: VirtAddr, size: usize) -> AxResult {
        self.validate_region(start, size)?;
        let end = start + size;

        while start < end {
            let area = match self.areas.find(start) {
                Some(area) => area,
                None => break,
            };
            let backend = area.backend().clone();
            let _end = area.end();
            let flags = area.flags();
            if let Backend::Alloc { populate, .. } = backend {
                if !populate {
                    for addr in PageIter4K::new(start, area.end().min(end)).unwrap() {
                        match self.pt.query(addr) {
                            Ok(_) => {}
                            // If the page is not mapped, try map it.
                            Err(PagingError::NotMapped) => {
                                if !backend.handle_page_fault(addr, flags, self) {
                                    return Err(AxError::NoMemory);
                                }
                            }
                            Err(_) => return Err(AxError::BadAddress),
                        };
                    }
                }
            }
            start = _end;
            assert!(start.is_aligned_4k());
        }
        /*
         *while let Some(area) = self.areas.find(start) {
         *    if start >= end {
         *        break;
         *    }
         *}
         */

        if start < end {
            // If the area is not fully mapped, we return ENOMEM.
            return ax_err!(NoMemory);
        }

        Ok(())
    }

    /// Removes mappings within the specified virtual address range.
    ///
    /// Returns an error if the address range is out of the address space or not
    /// aligned.
    pub fn unmap(&mut self, start: VirtAddr, size: usize) -> AxResult {
        self.validate_region(start, size)?;

        self.areas
            .unmap(start, size, &mut self.pt)
            .map_err(mapping_err_to_ax_err)?;
        Ok(())
    }

    /// To remove user area mappings from address space.
    pub fn unmap_user_areas(&mut self) -> AxResult {
        for area in self.areas.iter() {
            warn!("range:{:?} flag: {:?}", area.va_range(), area.flags());
            assert!(area.start().is_aligned_4k());
            assert!(area.size() % PAGE_SIZE_4K == 0);
            assert!(area.flags().contains(MappingFlags::USER));
            assert!(
                self.va_range
                    .contains_range(VirtAddrRange::from_start_size(area.start(), area.size())),
                "MemorySet contains out-of-va-range area"
            );
        }
        self.areas.clear(&mut self.pt).unwrap();

        #[cfg(feature = "heap")]
        {
            self.heap = None;
        }
        Ok(())
    }

    /// To remove a single mapping within the address space.
    pub fn unmap_area(&mut self, vaddr: VirtAddr) -> AxResult {
        if let Some(area) = self.areas.find_mut(vaddr) {
            assert!(area.start().is_aligned_4k());
            assert!(area.size() % PAGE_SIZE_4K == 0);
            assert!(area.flags().contains(MappingFlags::USER));
            assert!(
                self.va_range
                    .contains_range(VirtAddrRange::from_start_size(area.start(), area.size())),
                "MemorySet contains out-of-va-range area"
            );
            area.unmap_area(&mut self.pt)
                .map_err(mapping_err_to_ax_err)?;
        } else {
            return ax_err!(InvalidInput, "Invalid area addr");
        }
        self.areas.delete(vaddr);
        Ok(())
    }

    /// To process data in this area with the given function.
    ///
    /// Now it supports reading and writing data in the given interval.
    ///
    /// # Arguments
    /// - `start`: The start virtual address to process.
    /// - `size`: The size of the data to process.
    /// - `f`: The function to process the data, whose arguments are the start virtual address,
    ///   the offset and the size of the data.
    ///
    /// # Notes
    ///   The caller must ensure that the permission of the operation is allowed.
    fn process_area_data<F>(&self, start: VirtAddr, size: usize, f: F) -> AxResult
    where
        F: FnMut(VirtAddr, usize, usize),
    {
        Self::process_area_data_with_page_table(&self.pt, &self.va_range, start, size, f)
    }

    fn process_area_data_with_page_table<F>(
        pt: &PageTable,
        va_range: &VirtAddrRange,
        start: VirtAddr,
        size: usize,
        mut f: F,
    ) -> AxResult
    where
        F: FnMut(VirtAddr, usize, usize),
    {
        if !va_range.contains_range(VirtAddrRange::from_start_size(start, size)) {
            return ax_err!(InvalidInput, "address out of range");
        }
        let mut cnt = 0;
        // If start is aligned to 4K, start_align_down will be equal to start_align_up.
        let end_align_up = (start + size).align_up_4k();
        for vaddr in PageIter4K::new(start.align_down_4k(), end_align_up)
            .expect("Failed to create page iterator")
        {
            let (mut paddr, _, _) = pt.query(vaddr).map_err(|_| AxError::BadAddress)?;

            let mut copy_size = (size - cnt).min(PAGE_SIZE_4K);

            if copy_size == 0 {
                break;
            }
            if vaddr == start.align_down_4k() && start.align_offset_4k() != 0 {
                let align_offset = start.align_offset_4k();
                copy_size = copy_size.min(PAGE_SIZE_4K - align_offset);
                paddr += align_offset;
            }
            f(phys_to_virt(paddr), cnt, copy_size);
            cnt += copy_size;
        }
        Ok(())
    }

    /// To read data from the address space.
    ///
    /// # Arguments
    ///
    /// * `start` - The start virtual address to read.
    /// * `buf` - The buffer to store the data.
    pub fn read(&self, start: VirtAddr, buf: &mut [u8]) -> AxResult {
        self.process_area_data(start, buf.len(), |src, offset, read_size| unsafe {
            core::ptr::copy_nonoverlapping(src.as_ptr(), buf.as_mut_ptr().add(offset), read_size);
        })
    }

    /// To write data to the address space.
    ///
    /// # Arguments
    ///
    /// * `start_vaddr` - The start virtual address to write.
    /// * `buf` - The buffer to write to the address space.
    pub fn write(&self, start: VirtAddr, buf: &[u8]) -> AxResult {
        self.process_area_data(start, buf.len(), |dst, offset, write_size| unsafe {
            core::ptr::copy_nonoverlapping(buf.as_ptr().add(offset), dst.as_mut_ptr(), write_size);
        })
    }

    /// To write data to the address space.
    ///
    /// # Arguments
    ///
    /// * `start_vaddr` - The start virtual address to write.
    /// * `buf` - The buffer to write to the address space.
    pub fn fill_zero(&self, start: VirtAddr, size: usize) -> AxResult {
        self.process_area_data(start, size, |dst, offset, write_size| unsafe {
            core::ptr::write_bytes(dst.as_mut_ptr().add(offset), 0, write_size);
        })
    }

    /// Updates mapping within the specified virtual address range.
    /// Will considered COW
    /// Returns an error if the address range is out of the address space or not
    /// aligned.
    pub fn protect(&mut self, start: VirtAddr, size: usize, flags: MappingFlags) -> AxResult {
        // Populate the area first, which also checks the address range for us.
        self.populate_area(start, size)?;

        self.areas
            .protect(
                start,
                size,
                |old_flags| Some(old_flags.protect(flags)),
                &mut self.pt,
            )
            .map_err(mapping_err_to_ax_err)?;

        Ok(())
    }

    /// Removes all mappings in the address space.
    pub fn clear(&mut self) {
        self.areas.clear(&mut self.pt).unwrap();
    }

    /// Checks whether an access to the specified memory region is valid.
    ///
    /// Returns `true` if the memory region given by `range` is all mapped and
    /// has proper permission flags (i.e. containing `access_flags`).
    pub fn check_region_access(
        &self,
        mut range: VirtAddrRange,
        access_flags: MappingFlags,
    ) -> bool {
        let access_flags  = MappingFlags::unmark_cow(access_flags);
        // TODO: COW
        for area in self.areas.iter() {
            // warn!("{range:?} {access_flags:?}  {area:?}");
            if area.end() <= range.start {
                continue;
            }
            if area.start() > range.start {
                return false;
            }

            // This area overlaps with the memory region
            if !area.flags().contains(access_flags) {
                return false;
            }

            range.start = area.end();
            if range.is_empty() {
                return true;
            }
        }

        false
    }

    /// Handles a page fault at the given address.
    ///
    /// `access_flags` indicates the access type that caused the page fault.
    ///
    /// Returns `true` if the page fault is handled successfully (not a real
    /// fault).
    pub fn handle_page_fault(&mut self, vaddr: VirtAddr, access_flags: MappingFlags) -> bool {
        if !self.va_range.contains(vaddr) {
            return false;
        }
        if let Some(area) = self.areas.find(vaddr) {
            let orig_flags = area.flags();
            trace!("Page fault area flags: {:?}", orig_flags);
            trace!("Page fault pte flags: {:?}", self.pt.query(vaddr));

            if orig_flags.contains(access_flags) {
                return area
                    .backend()
                    .clone()
                    .handle_page_fault(vaddr, orig_flags, self);
                /*
                 *} else {
                 *    if let Ok((_, pte_flags, _)) = self.pt.query(vaddr) {
                 *        debug!("Page fault pte flags: {:?}", pte_flags);
                 *        #[cfg(feature = "COW")]
                 *        if (pte_flags.contains(MappingFlags::COW)
                 *            && orig_flags.contains(MappingFlags::WRITE))
                 *            || pte_flags.contains(MappingFlags::DEVICE)
                 *        {
                 *            warn!("pte flags: {:?}", pte_flags);
                 *            return area
                 *                .backend()
                 *                .clone()
                 *                .handle_page_fault(vaddr, pte_flags, self);
                 *        }
                 *        #[cfg(not(feature = "COW"))]
                 *        if pte_flags.contains(MappingFlags::DEVICE) {
                 *            return area
                 *                .backend()
                 *                .clone()
                 *                .handle_page_fault(vaddr, pte_flags, self);
                 *        }
                 *    }
                 */
            }
        }
        false
    }

    /// Clone a [`AddrSpace`] by re-mapping all [`MemoryArea`]s in a new page table and copying data in user space.
    pub fn clone_or_err(&mut self) -> AxResult<Self> {
        let mut new_aspace = Self::new_empty(self.base(), self.size())?;

        for area in self.areas.iter() {
            let backend = area.backend();
            // Remap the memory areajin the new address space.
            let flags = area.flags();

            let new_area = MemoryArea::new(area.start(), area.size(), None, flags, backend.clone());
            new_aspace
                .areas
                .map(new_area, &mut new_aspace.pt, false, None)
                .map_err(mapping_err_to_ax_err)?;

            if matches!(backend, Backend::Linear { .. }) {
                continue;
            }
            // Copy data from old memory area to new memory area.
            for vaddr in
                PageIter4K::new(area.start(), area.end()).expect("Failed to create page iterator")
            {
                let addr = match self.pt.query(vaddr) {
                    Ok((paddr, _, _)) => paddr,
                    // If the page is not mapped, skip it.
                    Err(PagingError::NotMapped) => continue,
                    Err(_) => return Err(AxError::BadAddress),
                };
                let new_addr = match new_aspace.pt.query(vaddr) {
                    Ok((paddr, _, _)) => paddr,
                    // If the page is not mapped, try map it.
                    Err(PagingError::NotMapped) => {
                        if !backend.handle_page_fault(vaddr, area.flags(), &mut new_aspace) {
                            return Err(AxError::NoMemory);
                        }
                        match new_aspace.pt.query(vaddr) {
                            Ok((paddr, _, _)) => paddr,
                            Err(_) => return Err(AxError::BadAddress),
                        }
                    }
                    Err(_) => return Err(AxError::BadAddress),
                };
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        phys_to_virt(addr).as_ptr(),
                        phys_to_virt(new_addr).as_mut_ptr(),
                        PAGE_SIZE_4K,
                    )
                };
            }
        }
        Ok(new_aspace)
    }

    /// Clone a [`AddrSpace`] by re-mapping all [`MemoryArea`]s in a new page table and change flags without coping data in user space.
    #[cfg(feature = "COW")]
    pub fn clone_on_write(&mut self) -> AxResult<Self> {
        use alloc::vec::Vec;
        use mmap::MmapFlags;

        use crate::backend::VmAreaType;

        let mut new_aspace = Self::new_empty(self.base(), self.size())?;
        #[cfg(feature = "heap")]
        {
            if let Some(heap) = &self.heap {
                let mut new_heap = HeapSpace::new(heap.base(), heap.max_size());
                new_heap.set_heap_top(heap.top());
                new_aspace.heap = Some(new_heap);
            }
        }

        for area in self.areas.iter() {
            debug!("copying : {:?}", area);
            // Remap the memory area in new address space.
            // area keeps the origin flags but pt flags will be marked as COW
            new_aspace
                .areas
                .insert(area.clone(), false)
                .map_err(mapping_err_to_ax_err)?;

            let mut pte_flags = area.flags();

            let should_mark_cow = {
                match area.backend() {
                    Backend::Alloc { va_type, populate } => match va_type {
                        VmAreaType::Mmap(mmio) => !mmio.flags().contains(MmapFlags::MAP_SHARED),
                        VmAreaType::Normal => true,
                        _ => false,
                    },
                    _ => false
                }
            };
            if should_mark_cow {
                pte_flags = MappingFlags::mark_cow(pte_flags);
                debug!("COW : {:?}", area);
            }
            // clone mappings
            // TODO: Better way to clone mapping
            // TODO: COW for page table
            for vaddr in
                PageIter4K::new(area.start(), area.end()).expect("Failed to create page iterator")
            {
                match self.pt.query(vaddr) {
                    Ok((paddr, _, page_size)) => {
                        new_aspace
                            .pt
                            .map(vaddr, paddr, page_size, pte_flags)
                            .unwrap();
                        self.pt
                            .remap(vaddr, paddr, pte_flags)
                            .map(|(_, tlb)| tlb.flush())
                            .unwrap();
                    }
                    // If the page is not mapped, skip it.
                    Err(PagingError::NotMapped) => continue,
                    Err(_) => return Err(AxError::BadAddress),
                };
            }
            /* May unmapped
             *if pte_flags.contains(MappingFlags::COW) {
             *    self.pt
             *        .protect_region(area.start(), area.size(), pte_flags, true);
             *}
             */
        }

        /*
         * // mark origin areas as COW
         *let cow_areas: Vec<(VirtAddr, usize, MappingFlags)> = new_aspace
         *    .areas
         *    .iter()
         *    .filter(|area| area.flags().contains(MappingFlags::USER & MappingFlags::WRITE))
         *    .map(|area| (area.start(), area.size(), area.flags()))
         *    .collect();
         *for (start, size, flags) in cow_areas {
         *    self.protect(start, size, MappingFlags::mark_cow(flags))?;
         *}
         */

        Ok(new_aspace)
    }
}

impl fmt::Debug for AddrSpace {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("AddrSpace")
            .field("va_range", &self.va_range)
            .field("page_table_root", &self.pt.root_paddr())
            .field("areas", &self.areas)
            .finish()
    }
}

impl Drop for AddrSpace {
    fn drop(&mut self) {
        self.clear();
    }
}
