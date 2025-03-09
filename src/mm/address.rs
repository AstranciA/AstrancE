use core::{
    fmt::{self, Debug, Formatter},
    iter::Step,
};

use crate::config::PAGE_SIZE;

use super::page_table::PageTableEntry;

/// page offset, 12 bits.
pub const PAGE_SIZE_BITS: usize = 0xc;
pub const PA_WIDTH_SV39: usize = 56;
pub const VA_WIDTH_SV39: usize = 39;
pub const PPN_WIDTH_SV39: usize = PA_WIDTH_SV39 - PAGE_SIZE_BITS;
pub const VPN_WIDTH_SV39: usize = PA_WIDTH_SV39 - PAGE_SIZE_BITS;

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct PhysAddr(pub usize);
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct VirtAddr(pub usize);
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct PhysPageNum(pub usize);
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct VirtPageNum(pub usize);

/// Debugging
impl Debug for VirtAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("VA:{:#x}", self.0))
    }
}
impl Debug for VirtPageNum {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("VPN:{:#x}", self.0))
    }
}
impl Debug for PhysAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("PA:{:#x}", self.0))
    }
}
impl Debug for PhysPageNum {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("PPN:{:#x}", self.0))
    }
}

impl PhysAddr {
    /// in page offset
    pub fn page_offset(&self) -> usize {
        self.0 & (PAGE_SIZE - 1)
    }

    pub fn floor(&self) -> PhysPageNum {
        PhysPageNum(self.0 / PAGE_SIZE)
    }

    pub fn ceil(&self) -> PhysPageNum {
        PhysPageNum((self.0 + PAGE_SIZE - 1) / PAGE_SIZE)
    }
}

/// mask higher bits
impl From<usize> for PhysAddr {
    fn from(value: usize) -> Self {
        Self(value & ((1 << PA_WIDTH_SV39) - 1))
    }
}

impl Into<usize> for PhysAddr {
    fn into(self) -> usize {
        self.0
    }
}

impl From<PhysAddr> for PhysPageNum {
    fn from(value: PhysAddr) -> Self {
        assert_eq!(value.page_offset(), 0);
        value.floor()
    }
}

impl From<PhysPageNum> for PhysAddr {
    fn from(value: PhysPageNum) -> PhysAddr {
        (value.0 << PAGE_SIZE_BITS).into()
    }
}

impl PhysPageNum {
    pub fn get_pte_array(&self) -> &'static mut [PageTableEntry] {
        let pa: PhysAddr = self.clone().into();
        unsafe { core::slice::from_raw_parts_mut(pa.0 as *mut PageTableEntry, 512) }
    }
    pub fn get_byte_array(&self) -> &'static mut [u8] {
        let pa: PhysAddr = self.clone().into();
        unsafe { core::slice::from_raw_parts_mut(pa.0 as *mut u8, 4096) }
    }
    pub fn get_mut<T>(&self) -> &'static mut T {
        let pa: PhysAddr = self.clone().into();
        unsafe { (pa.0 as *mut T).as_mut().unwrap() }
    }
}

impl From<usize> for PhysPageNum {
    fn from(value: usize) -> Self {
        Self(value & ((1 << PPN_WIDTH_SV39) - 1))
    }
}
impl Into<usize> for PhysPageNum {
    fn into(self) -> usize {
        self.0
    }
}

impl VirtAddr {
    /// in page offset
    pub fn page_offset(&self) -> usize {
        self.0 & PAGE_SIZE - 1
    }

    pub fn floor(&self) -> VirtPageNum {
        VirtPageNum(self.0 / PAGE_SIZE)
    }

    pub fn ceil(&self) -> VirtPageNum {
        VirtPageNum((self.0 + PAGE_SIZE - 1) / PAGE_SIZE)
    }
}

/// mask higher bits
impl From<usize> for VirtAddr {
    fn from(value: usize) -> Self {
        Self(value & ((1 << VA_WIDTH_SV39) - 1))
    }
}
impl From<VirtAddr> for usize {
    fn from(val: VirtAddr) -> Self {
        val.0
    }
}

impl From<VirtAddr> for VirtPageNum {
    fn from(value: VirtAddr) -> Self {
        assert_eq!(value.page_offset(), 0);
        value.floor()
    }
}

impl From<VirtPageNum> for VirtAddr {
    fn from(value: VirtPageNum) -> Self {
        (value.0 << PAGE_SIZE_BITS).into()
    }
}

impl VirtPageNum {
    pub fn indexes(&self) -> [usize; 3] {
        let mut vpn = self.0;
        let mut idx = [0usize; 3];
        for i in (0..3).rev() {
            idx[i] = vpn & 511;
            vpn >>= 9;
        }
        idx
    }
}

impl From<usize> for VirtPageNum {
    /// WARN: not aligned
    fn from(value: usize) -> Self {
        Self(value & ((1 << PPN_WIDTH_SV39) - 1))
    }
}
impl From<VirtPageNum> for usize {
    fn from(val: VirtPageNum) -> Self {
        val.0
    }
}

impl Step for VirtPageNum {
    fn steps_between(start: &Self, end: &Self) -> (usize, Option<usize>) {
        usize::steps_between(&start.0, &end.0)
    }

    fn forward_checked(start: Self, count: usize) -> Option<Self> {
        usize::forward_checked(start.0, count).map(|x| x.into())
    }

    fn backward_checked(start: Self, count: usize) -> Option<Self> {
        usize::backward_checked(start.0, count).map(|x| x.into())
    }
}
