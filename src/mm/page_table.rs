use alloc::vec;
use alloc::vec::Vec;
use bitflags::Flags;
use riscv::register::satp::Satp;

use crate::config::PAGE_SIZE;

use super::{
    address::{PhysPageNum, VirtAddr, VirtPageNum, PPN_WIDTH_SV39},
    frame_allocator::{frame_alloc, FrameTracker},
};

const PTE_SIZE_BITS: usize = 10;

bitflags! {
    /// page table entry flags
    pub struct PTEFlags: u8 {
        const V = 1 << 0;
        const R = 1 << 1;
        const W = 1 << 2;
        const X = 1 << 3;
        const U = 1 << 4;
        const G = 1 << 5;
        const A = 1 << 6;
        const D = 1 << 7;
    }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct PageTableEntry(pub usize);

impl PageTableEntry {
    pub fn new(ppn: PhysPageNum, flags: PTEFlags) -> Self {
        PageTableEntry((ppn.0 << PTE_SIZE_BITS) | (flags.bits() as usize))
    }
    pub fn empty() -> Self {
        PageTableEntry(0)
    }
    pub fn flags(&self) -> PTEFlags {
        PTEFlags::from_bits_truncate(self.0 as u8)
    }

    pub fn ppn(&self) -> PhysPageNum {
        (self.0 >> PTE_SIZE_BITS).into()
    }

    pub fn is_valid(&self) -> bool {
        self.flags().contains(PTEFlags::V)
    }
    pub fn is_readable(&self) -> bool {
        self.flags().contains(PTEFlags::R)
    }
    pub fn is_writable(&self) -> bool {
        self.flags().contains(PTEFlags::W)
    }
    pub fn is_executable(&self) -> bool {
        self.flags().contains(PTEFlags::X)
    }
    pub fn is_user(&self) -> bool {
        self.flags().contains(PTEFlags::U)
    }
    pub fn is_global(&self) -> bool {
        self.flags().contains(PTEFlags::G)
    }
    pub fn is_accessed(&self) -> bool {
        self.flags().contains(PTEFlags::A)
    }
    pub fn is_dirty(&self) -> bool {
        self.flags().contains(PTEFlags::D)
    }
}

pub struct PageTable {
    pub root_ppn: PhysPageNum,
    frames: Vec<FrameTracker>,
}
impl PageTable {
    pub fn new() -> Self {
        let frame = frame_alloc().unwrap();
        PageTable {
            root_ppn: frame.ppn,
            frames: vec![frame],
        }
    }

    pub fn token(&self) -> Satp {
        let mut satp = Satp::from_bits(self.root_ppn.0);
        satp.set_mode(riscv::register::satp::Mode::Sv39);
        satp
    }

    pub fn map(&mut self, vpn: VirtPageNum, ppn: PhysPageNum, flags: PTEFlags) {
        let pte = self.find_pte_create(vpn).unwrap();
        // TODO: Do anything else
        assert!(!pte.is_valid(), "vpn {:?} is mapped before mapping", vpn);
        *pte = PageTableEntry::new(ppn, flags | PTEFlags::V);
    }

    pub fn unmap(&mut self, vpn: VirtPageNum) {
        let pte = self.find_pte(vpn).unwrap();
        assert!(pte.is_valid(), "vpn {:?} is invalid before unmapping", vpn);
        *pte = PageTableEntry::empty();
    }

    fn find_pte_create(&mut self, vpn: VirtPageNum) -> Option<&mut PageTableEntry> {
        let idxs = vpn.indexes();
        let mut ppn = self.root_ppn;
        let mut result: Option<&mut PageTableEntry> = None;

        for i in 0..3 {
            let pte = &mut ppn.get_pte_array()[idxs[i]];
            if i == 2 {
                result = Some(pte);
                break;
            }
            if !pte.is_valid() {
                let frame = frame_alloc().unwrap();
                //println!("new frame at: {:?}", frame.ppn);
                *pte = PageTableEntry::new(frame.ppn, PTEFlags::V);
                self.frames.push(frame);
            }
            ppn = pte.ppn();
        }
        result
    }

    fn find_pte(&self, vpn: VirtPageNum) -> Option<&mut PageTableEntry> {
        let idxs = vpn.indexes();
        let mut ppn = self.root_ppn;
        let mut result: Option<&mut PageTableEntry> = None;

        for i in 0..3 {
            let pte = &mut ppn.get_pte_array()[idxs[i]];
            if i == 2 {
                result = Some(pte);
                break;
            }
            if !pte.is_valid() {
                return None;
            }
            ppn = pte.ppn();
        }
        result
    }

    pub fn from_token(satp: Satp) -> Self {
        Self {
            root_ppn: satp.ppn().into(),
            frames: vec![],
        }
    }
    pub fn translate(&self, vpn: VirtPageNum) -> Option<PageTableEntry> {
        self.find_pte(vpn).copied()
    }
    pub fn translated_byte_buffer(token: Satp, ptr: *const u8, len: usize) -> Vec<&'static [u8]> {
        let page_table = PageTable::from_token(token);

        let start_va = VirtAddr::from(ptr as usize);
        let end_va = VirtAddr::from(ptr as usize + len);

        (start_va.floor()..end_va.ceil())
            .map(|vpn| {
                let ppn = page_table.translate(vpn).unwrap().ppn();
                let page_start: usize =VirtAddr::from(vpn).into();

                let slice_start = start_va.max(page_start.into()).page_offset();
                let slice_end = end_va.min((page_start + PAGE_SIZE).into()).page_offset();
                &ppn.get_byte_array()[slice_start..slice_end]
            })
            .filter(|slice| !slice.is_empty()) // WARN: 过滤空切片?
            .collect()
    }
}
