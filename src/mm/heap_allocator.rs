use buddy_system_allocator::LockedHeap;

use crate::config::KERNEL_HEAP_SIZE;

// TODO: 64? from where?
#[global_allocator]
static HEAP_ALLOCATOR: LockedHeap<64> = LockedHeap::empty();

static mut HEAP_SPACE: [u8; KERNEL_HEAP_SIZE] = [0; KERNEL_HEAP_SIZE];

pub fn init_heap() {
    unsafe {
        HEAP_ALLOCATOR
            .lock()
            .init(HEAP_SPACE.as_ptr() as usize, KERNEL_HEAP_SIZE)
    };
}

/// TODO: do anything else?
#[alloc_error_handler]
pub fn handle_alloc_error(layout: core::alloc::Layout)->! {
    panic!("Heap allocation error: {:?}", layout)
}
