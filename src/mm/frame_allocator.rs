use alloc::vec::Vec;

use crate::{config::MEMORY_END, mm::address::PhysAddr, sync::UPSafeCell};

use super::address::PhysPageNum;

type FrameAllocatorImpl = StackFrameAlloctor;

lazy_static! {
    pub static ref FRAME_ALLOCATOR: UPSafeCell<FrameAllocatorImpl> =
        unsafe { UPSafeCell::new(FrameAllocatorImpl::new()) };
}

/// TODO: after ekernel ??
pub fn init_frame_allocator() {
    extern "C" {
        fn ekernel();
    }

    FRAME_ALLOCATOR.exclusive_access().init(
        PhysAddr::from(ekernel as usize).ceil(),
        PhysAddr::from(MEMORY_END).floor(),
    );
}

pub fn frame_alloc() -> Option<FrameTracker> {
    FRAME_ALLOCATOR
        .exclusive_access()
        .allocate()
        .map(FrameTracker::new)
}

pub fn frame_dealloc(ppn: PhysPageNum) {
    FRAME_ALLOCATOR.exclusive_access().dealloc(ppn).unwrap();
}

trait FrameAllocator {
    fn new() -> Self;
    fn allocate(&mut self) -> Option<PhysPageNum>;
    fn dealloc(&mut self, ppn: PhysPageNum) -> Result<(), &str>;
}

/// TODO: other frame allocator implementations
pub struct StackFrameAlloctor {
    current: PhysPageNum,
    end: PhysPageNum,
    recycled: Vec<PhysPageNum>,
}

impl StackFrameAlloctor {
    pub fn init(&mut self, start: PhysPageNum, end: PhysPageNum) {
        self.current = start;
        self.end = end;
    }
}

impl FrameAllocator for StackFrameAlloctor {
    fn new() -> Self {
        Self {
            current: PhysPageNum(0),
            end: PhysPageNum(0),
            recycled: Vec::new(),
        }
    }

    fn allocate(&mut self) -> Option<PhysPageNum> {
        if let Some(frame) = self.recycled.pop() {
            Some(frame)
        } else if self.current >= self.end {
            None
        } else {
            let frame = self.current;
            self.current.0 += 1;
            Some(frame)
        }
    }

    fn dealloc(&mut self, ppn: PhysPageNum) -> Result<(), &str> {
        if ppn >= self.current || self.recycled.contains(&ppn) {
            Err("Invalid frame to deallocate")
        } else {
            Ok(())
        }
    }
}

pub struct FrameTracker {
    pub ppn: PhysPageNum,
}

impl FrameTracker {
    pub fn new(ppn: PhysPageNum) -> Self {
        FrameTracker { ppn }
    }
}

impl Drop for FrameTracker {
    fn drop(&mut self) {
        frame_dealloc(self.ppn);
    }
}
