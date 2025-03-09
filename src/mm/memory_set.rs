use alloc::{collections::btree_map::BTreeMap, sync::Arc, vec::Vec};
use riscv::register::satp::{self, Satp};

use crate::{
    config::{MEMORY_END, PAGE_SIZE, TRAMPOLINE, TRAP_CONTEXT, USER_STACK_SIZE},
    sync::UPSafeCell,
};

use super::{
    address::{PhysAddr, PhysPageNum, VirtAddr, VirtPageNum},
    frame_allocator::{frame_alloc, FrameTracker},
    page_table::{PTEFlags, PageTable},
};

lazy_static! {
    pub static ref KERNEL_SPACE: Arc<UPSafeCell<MemorySet>> =
        Arc::new(UPSafeCell::new(MemorySet::new_kernel()));
}

pub struct MapArea {
    vpn_range: VPNRange,
    data_frames: BTreeMap<VirtPageNum, FrameTracker>,
    map_type: MapType,
    map_perm: MapPermission,
}

impl MapArea {
    pub fn new(
        start_va: VirtAddr,
        end_va: VirtAddr,
        map_type: MapType,
        map_perm: MapPermission,
    ) -> Self {
        let start_vpn = start_va.floor();
        let end_vpn = end_va.ceil();
        Self {
            vpn_range: start_vpn..end_vpn,
            data_frames: BTreeMap::new(),
            map_type,
            map_perm,
        }
    }

    pub fn map(&mut self, page_table: &mut PageTable) {
        for vpn in self.vpn_range.clone() {
            self.map_one(page_table, vpn);
        }
    }

    pub fn unmap(&mut self, page_table: &mut PageTable) {
        for vpn in self.vpn_range.clone() {
            self.unmap_one(page_table, vpn);
        }
    }

    pub fn copy_data(&mut self, page_table: &mut PageTable, data: &[u8]) {
        assert_eq!(self.map_type, MapType::Framed);

        println!(
            "copy_data: {} {}",
            data.chunks(PAGE_SIZE).count(),
            self.vpn_range.clone().count()
        );

        assert!(
            data.chunks(PAGE_SIZE).count() <= self.vpn_range.clone().count(),
            "Not enough virtual pages to hold data"
        );
        /*
         *let mut start: usize = 0;
         *let mut current_vpn = self.vpn_range.start;
         *let len = data.len();
         *loop {
         *    let src = &data[start..len.min(start + PAGE_SIZE)];
         *    let dst = &mut page_table.translate(current_vpn).unwrap().ppn().get_byte_array()[..src.len()];
         *    dst.copy_from_slice(src);
         *    start += PAGE_SIZE;
         *    if start >= len {
         *        break;
         *    }
         *    current_vpn.step();
         *}
         */

        data.chunks(PAGE_SIZE)
            .zip(self.vpn_range.clone())
            .for_each(|(src_chunk, vpn)| {
                let dst = page_table.translate(vpn).unwrap().ppn().get_byte_array();

                // handle unaligned data length
                // WARN: page is not clean
                let len = src_chunk.len().min(dst.len());
                dst[..len].copy_from_slice(&src_chunk[..len]);
            });
    }

    pub fn map_one(&mut self, page_table: &mut PageTable, vpn: VirtPageNum) {
        let ppn: PhysPageNum;
        match self.map_type {
            MapType::Identical => {
                ppn = PhysPageNum(vpn.into());
            }
            MapType::Framed => {
                let frame = frame_alloc().unwrap();
                ppn = frame.ppn;
                self.data_frames.insert(vpn, frame);
            }
        }

        let pte_flags = PTEFlags::from_bits(self.map_perm.bits()).unwrap();
        page_table.map(vpn, ppn, pte_flags);
    }

    pub fn unmap_one(&mut self, page_table: &mut PageTable, vpn: VirtPageNum) {
        match self.map_type {
            MapType::Framed => {
                self.data_frames.remove(&vpn);
            }
            MapType::Identical => {
                //warn!("Try to unmap identical mapping")
            }
        }
        page_table.unmap(vpn);
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum MapType {
    Identical,
    Framed,
}

bitflags! {
    pub struct MapPermission: u8 {
        const R = 1 << 1;
        const W = 1 << 2;
        const X = 1 << 3;
        const U = 1<<4;
    }
}

pub struct MemorySet {
    pub page_table: PageTable,
    pub areas: Vec<MapArea>,
}

impl MemorySet {
    pub fn new_bare() -> Self {
        Self {
            page_table: PageTable::new(),
            areas: Vec::new(),
        }
    }

    pub fn token(&self) -> Satp {
        self.page_table.token()
    }

    pub fn activate(&self) {
        let satp = self.page_table.token();
        //satp.set_mode(riscv::register::satp::Mode::Sv39);
        unsafe {
            riscv::register::satp::set(
                riscv::register::satp::Mode::Sv39,
                0,
                self.page_table.root_ppn.0,
            )
        };
        /*
         *unsafe {
         *    satp::write(satp);
         *    asm!("sfence.vma");
         *}
         */
    }

    pub fn push(&mut self, mut map_area: MapArea, data: Option<&[u8]>) {
        map_area.map(&mut self.page_table);
        if let Some(data) = data {
            map_area.copy_data(&mut self.page_table, data);
        }
        self.areas.push(map_area);
    }

    pub fn insert_framed_area(
        &mut self,
        start_va: VirtAddr,
        end_va: VirtAddr,
        permission: MapPermission,
    ) {
        self.push(
            MapArea::new(start_va, end_va, MapType::Framed, permission),
            None,
        );
    }

    pub fn new_kernel() -> Self {
        let mut memory_set = Self::new_bare();
        memory_set.map_trampoline();

        extern "C" {
            fn stext();
            fn etext();
            fn srodata();
            fn erodata();
            fn sdata();
            fn edata();
            fn sbss_with_stack();
            fn ebss();
            fn ekernel();
        }

        let sections: [(&str, usize, usize, MapPermission); 5] = [
            (
                ".text",
                stext as usize,
                etext as usize,
                MapPermission::R | MapPermission::X,
            ),
            (
                ".rodata",
                srodata as usize,
                erodata as usize,
                MapPermission::R,
            ),
            (
                ".data",
                sdata as usize,
                edata as usize,
                MapPermission::R | MapPermission::W,
            ),
            (
                ".sbss_with_stack",
                sbss_with_stack as usize,
                ebss as usize,
                MapPermission::R | MapPermission::W,
            ),
            (
                "physical memory",
                ekernel as usize,
                MEMORY_END,
                MapPermission::R | MapPermission::W,
            ),
        ];
        fn print_section_info(name: &str, start: usize, end: usize) {
            kprintln!("{:8}: [{:#x}, {:#x})", name, start, end);
        }
        for (name, start, end, perm) in sections {
            print_section_info(name, start, end);
            kprintln!("mapping {} section", name);
            memory_set.push(
                MapArea::new(start.into(), end.into(), MapType::Identical, perm),
                None,
            );
        }

        memory_set
    }

    fn map_trampoline(&mut self) {
        extern "C" {
            fn strampoline();
        }
        self.page_table.map(
            VirtAddr::from(TRAMPOLINE).into(),
            PhysAddr::from(strampoline as usize).into(),
            PTEFlags::R | PTEFlags::X,
        );
    }

    pub fn from_elf(elf_data: &[u8]) -> (Self, usize, usize) {
        let mut memory_set = Self::new_bare();
        // map trampoline
        memory_set.map_trampoline();
        // map program headers of elf, with U flag
        let elf = xmas_elf::ElfFile::new(elf_data).unwrap();
        let elf_header = elf.header;
        let magic = elf_header.pt1.magic;
        assert_eq!(magic, [0x7f, 0x45, 0x4c, 0x46], "invalid elf!");
        let ph_count = elf_header.pt2.ph_count();
        let mut max_end_vpn = VirtPageNum(0);
        for i in 0..ph_count {
            let ph = elf.program_header(i).unwrap();
            if ph.get_type().unwrap() == xmas_elf::program::Type::Load {
                let start_va: VirtAddr = (ph.virtual_addr() as usize).into();
                let end_va: VirtAddr = ((ph.virtual_addr() + ph.mem_size()) as usize).into();
                let mut map_perm = MapPermission::U;
                let ph_flags = ph.flags();
                if ph_flags.is_read() {
                    map_perm |= MapPermission::R;
                }
                if ph_flags.is_write() {
                    map_perm |= MapPermission::W;
                }
                if ph_flags.is_execute() {
                    map_perm |= MapPermission::X;
                }
                println!("mapping program: [{:?}, {:?})", start_va, end_va);
                let map_area = MapArea::new(start_va, end_va, MapType::Framed, map_perm);
                max_end_vpn = map_area.vpn_range.end;
                memory_set.push(
                    map_area,
                    Some(&elf.input[ph.offset() as usize..(ph.offset() + ph.file_size()) as usize]),
                );
            }
        }
        // map user stack with U flags
        let max_end_va: VirtAddr = max_end_vpn.into();
        let mut user_stack_bottom: usize = max_end_va.into();
        // guard page
        user_stack_bottom += PAGE_SIZE;
        let user_stack_top = user_stack_bottom + USER_STACK_SIZE;
        memory_set.push(
            MapArea::new(
                user_stack_bottom.into(),
                user_stack_top.into(),
                MapType::Framed,
                MapPermission::R | MapPermission::W | MapPermission::U,
            ),
            None,
        );
        // used in sbrk
        memory_set.push(
            MapArea::new(
                user_stack_top.into(),
                user_stack_top.into(),
                MapType::Framed,
                MapPermission::R | MapPermission::W | MapPermission::U,
            ),
            None,
        );
        // map TrapContext
        memory_set.push(
            MapArea::new(
                TRAP_CONTEXT.into(),
                TRAMPOLINE.into(),
                MapType::Framed,
                MapPermission::R | MapPermission::W,
            ),
            None,
        );
        (
            memory_set,
            user_stack_top,
            elf.header.pt2.entry_point() as usize,
        )

        /*
         *        let mut memory_set = Self::new_bare();
         *        memory_set.map_trampoline();
         *
         *        let mut max_end_vpn = VirtPageNum(0);
         *
         *        // map program headers of elf, with U flag
         *        let elf = elf::ElfBytes::<LittleEndian>::minimal_parse(elf_data).unwrap();
         *        let ehdr = elf.ehdr;
         *        // TODO: check elf header
         *        //assert_eq!(ehdr.e_indenr[..4], [0x7f, 0x45, 0x4c, 0x46], "invalid elf!");
         *
         *        let phdrs = elf.segments().unwrap();
         *        println!("program headers: {:?}", phdrs);
         *        for ph in phdrs {
         *            if ph.p_type & elf::abi::PT_LOAD == 0 {
         *                continue;
         *            }
         *
         *            let start_va: VirtAddr = (ph.p_vaddr as usize).into();
         *            let end_va: VirtAddr = ((ph.p_vaddr + ph.p_memsz) as usize).into();
         *            println!("mapping program: [{:?}, {:?})", start_va, end_va);
         *
         *            let mut map_perm = MapPermission::U;
         *            let ph_flags = ph.p_flags;
         *            if ph_flags & elf::abi::PF_R != 0 {
         *                map_perm |= MapPermission::R;
         *            }
         *            if ph_flags & elf::abi::PF_W != 0 {
         *                map_perm |= MapPermission::W;
         *            }
         *            if ph_flags & elf::abi::PF_X != 0 {
         *                map_perm |= MapPermission::X;
         *            }
         *
         *            let map_area = MapArea::new(start_va, end_va, MapType::Framed, map_perm);
         *            // WARN: unnecessary max??
         *            //max_end_vpn = max_end_vpn.max(map_area.vpn_range.end);
         *            max_end_vpn = max_end_vpn.max(map_area.vpn_range.end);
         *            let s_data = elf.segment_data(&ph).unwrap();
         *            memory_set.push(
         *                map_area,
         *                //Some(&s_data[ph.p_offset as usize..(ph.p_offset + ph.p_filesz) as usize]),
         *                Some(&s_data[..ph.p_filesz as usize]),
         *            );
         *        }
         *
         *        let max_end_va: VirtAddr = max_end_vpn.into();
         *        let mut user_stack_bottom: usize = max_end_va.into();
         *        // guard page
         *        user_stack_bottom += PAGE_SIZE;
         *
         *        // map user stack
         *        let user_stack_top = user_stack_bottom + USER_STACK_SIZE;
         *        memory_set.push(
         *            MapArea::new(
         *                user_stack_bottom.into(),
         *                user_stack_top.into(),
         *                MapType::Framed,
         *                MapPermission::R | MapPermission::W | MapPermission::U,
         *            ),
         *            None,
         *        );
         *        memory_set.push(
         *            MapArea::new(
         *                user_stack_top.into(),
         *                user_stack_top.into(),
         *                MapType::Framed,
         *                MapPermission::R | MapPermission::W | MapPermission::U,
         *            ),
         *            None,
         *        );
         *
         *        // map TrapContext
         *        memory_set.push(
         *            MapArea::new(
         *                TRAP_CONTEXT.into(),
         *                TRAMPOLINE.into(),
         *                MapType::Framed,
         *                MapPermission::R | MapPermission::W,
         *            ),
         *            None,
         *        );
         *        (memory_set, user_stack_top, ehdr.e_entry as usize)
         */
    }
}

type VPNRange = core::ops::Range<VirtPageNum>;
/*
 *#[derive(Clone)]
 *struct VPNRange(core::ops::Range<VirtPageNum>);
 *impl Deref for VPNRange {
 *    type Target = core::ops::Range<VirtPageNum>;
 *
 *    fn deref(&self) -> &Self::Target {
 *        self.0
 *    }
 *}
 */
