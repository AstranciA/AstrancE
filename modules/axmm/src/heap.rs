use crate::AddrSpace;
use axhal::mem::PAGE_SIZE_4K;
use axhal::paging::MappingFlags;
use core::sync::atomic::{AtomicUsize, Ordering};
use memory_addr::{MemoryAddr, VirtAddr};

#[derive(Debug)]
pub struct HeapSpace {
    max_heap_size: usize,
    heap_base: usize,
    heap_top: AtomicUsize,
}

#[allow(unused)]
impl HeapSpace {
    pub fn new(heap_bottom: VirtAddr, max_size: usize) -> Self {
        Self {
            max_heap_size: max_size,
            heap_base: heap_bottom.as_usize(),
            heap_top: AtomicUsize::new(heap_bottom.as_usize()),
        }
    }

    fn set_max_heap_size(&mut self, max_heap_size: usize) {
        self.max_heap_size = max_heap_size;
    }
    pub fn top(&self) -> VirtAddr {
        VirtAddr::from_usize(self.heap_top.load(Ordering::Acquire))
    }

    pub fn base(&self) -> VirtAddr {
        VirtAddr::from_usize(self.heap_base)
    }

    pub fn max_size(&self) -> usize {
        self.max_heap_size
    }

    pub fn size(&self) -> usize {
        self.top() - self.base()
    }

    pub(crate) fn set_heap_top(&self, top: VirtAddr) -> VirtAddr {
        assert!(
            (top < self.base().offset(self.max_heap_size as isize)) && (top >= self.base()),
            "heap top must be in [{:x}, {:x}), but get {top:x}",
            self.heap_base,
            self.heap_base + self.max_heap_size
        );

        self.heap_top.store(top.as_usize(), Ordering::Release);

        VirtAddr::from_usize(self.heap_base)
    }

    pub fn set_heap_size(&self, size: usize) -> VirtAddr {
        self.set_heap_top(self.base() + size)
    }

    fn move_heap_top(&self, offset: isize) -> VirtAddr {
        let new_top = VirtAddr::from_usize(self.heap_base).offset(offset);
        self.set_heap_top(new_top)
    }
}

impl AddrSpace {
    pub fn init_heap(&mut self, heap_bottom: VirtAddr, max_size: usize) {
        assert!(self.heap.is_none(), "heap is already initialized");
        let heap = HeapSpace::new(heap_bottom, max_size);

        // alloc a page to avoid zero size area.
        // FIXME: lazy alloc
        self.map_alloc(
            heap.base(),
            PAGE_SIZE_4K,
            MappingFlags::READ | MappingFlags::WRITE | MappingFlags::USER,
            true,
        )
        .expect("heap mapping failed");
        self.heap = Some(heap);
    }

    pub fn heap(&self) -> &HeapSpace {
        self.heap.as_ref().expect("Heap is not initialized.")
    }

    pub fn set_heap_top(&mut self, top: VirtAddr) -> VirtAddr {
        let heap = self.heap();
        debug!("setting heap top from {:?} to {:?}", heap.top(), top);
        if top != self.heap().top() {
            self.heap().set_heap_top(top);
            // TODO: wrong flags if area is taken place by mmap!!!
            self.areas
                .adjust_area(
                    heap.base(),
                    heap.base(),
                    top.align_up_4k(),
                    &mut self.pt,
                )
                .unwrap();
        }
        top
    }
    pub fn set_heap_size(&mut self, size: usize) -> VirtAddr {
        let heap_base = self.heap().base();
        self.set_heap_top(heap_base + size)
    }
}
