use core::ffi::CStr;
use core::ops::Deref;

use alloc::format;
use alloc::string::ToString;
use alloc::{string::String, vec::Vec};
use axerrno::{AxError, AxResult};
use axhal::{
    mem::{MemoryAddr, PAGE_SIZE_4K, VirtAddr},
    paging::MappingFlags,
};
use kernel_elf_parser::{AuxvEntry, ELFParser};
use memory_addr::{VirtAddrRange, va_range};
use xmas_elf::program::Type;
use xmas_elf::{
    ElfFile,
    header::{self, Header},
    program::{Flags, SegmentData},
};

/// 持有ELF文件内容和解析结果的包装类型
pub struct OwnedElfFile {
    _content: Vec<u8>, // 保持所有权但不直接使用，下划线前缀表示这是一个仅用于所有权的字段
    elf_file: ElfFile<'static>, // 实际上这个'static引用指向_content
    file_path: String,
}
impl OwnedElfFile {
    pub fn new(app_path: &str, content: Vec<u8>) -> AxResult<Self> {
        // 创建引用content的切片，但绕过生命周期检查
        // 安全性由结构体保证：elf_file不会比_content活得更久
        let slice = unsafe { core::slice::from_raw_parts(content.as_ptr(), content.len()) };
        let elf_file = ElfFile::new(slice).map_err(|_| AxError::InvalidData)?;
        Ok(Self {
            _content: content,
            elf_file,
            file_path: app_path.into(),
        })
    }
}
// 允许OwnedElfFile被当作ElfFile使用
impl Deref for OwnedElfFile {
    type Target = ElfFile<'static>;

    fn deref(&self) -> &Self::Target {
        &self.elf_file
    }
}

/// The information of a given ELF file
pub struct ELFInfo {
    pub base: VirtAddr,
    /// The entry point of the ELF file
    pub entry: VirtAddr,
    /// The segments of the ELF file
    pub segments: Vec<ELFSegment>,
    /// The auxiliary vectors of the ELF file
    pub auxv: [AuxvEntry; 16],

    _elf: OwnedElfFile,
}

impl ELFInfo {
    pub fn new(
        elf: OwnedElfFile,
        uspace_base: VirtAddr,
        interp_base: Option<VirtAddr>,
        bias: Option<isize>,
    ) -> AxResult<Self> {
        let elf_header = elf.header;

        // will be checked in parser
        //Self::assert_magic(&elf_header);

        Self::check_arch(&elf_header)
            .inspect_err(|e| error!("{}", *e))
            .map_err(|_| AxError::Unsupported)?;
        let elf_parser = kernel_elf_parser::ELFParser::new(
            &elf,
            interp_base.map(|va| va.as_usize()).unwrap_or(0),
            bias,
            uspace_base.as_usize(),
        )
        .map_err(|_| AxError::InvalidData)?;

        let elf_offset = elf_parser.base();

        let segments = elf
            .program_iter()
            .filter(|ph| {
                ph.get_type() == Ok(xmas_elf::program::Type::Load)
                    || ph.get_type() == Ok(xmas_elf::program::Type::Tls)
            })
            .map(|ph| {
                let st_va = VirtAddr::from(ph.virtual_addr() as usize) + elf_offset;
                let st_va_align: VirtAddr = st_va.align_down_4k();

                let ed_vaddr_align = VirtAddr::from((ph.virtual_addr() + ph.mem_size()) as usize)
                    .align_up_4k()
                    + elf_offset;

                let ph_flags = ph.flags();
                let flags = ELFSegment::into_to_mapping_flag(ph_flags);

                let size = ed_vaddr_align.as_usize() - st_va_align.as_usize();

                let data: &'static [u8] = match ph.get_data(&elf).unwrap() {
                    SegmentData::Undefined(data) => data,
                    _ => panic!("failed to get ELF segment data"),
                };

                ELFSegment {
                    flags,
                    start_va: st_va_align,
                    size,
                    data,
                    offset: st_va.align_offset_4k(),
                    type_: ph.get_type().unwrap(),
                }
            })
            .collect();

        Ok(ELFInfo {
            base: elf_offset.into(),
            entry: VirtAddr::from(elf.header.pt2.entry_point() as usize + elf_offset),
            segments,
            auxv: elf_parser.auxv_vector(PAGE_SIZE_4K),
            _elf: elf,
        })
    }

    pub fn assert_magic(elf_header: &Header) {
        assert_eq!(elf_header.pt1.magic, *b"\x7fELF", "invalid elf!");
    }

    pub fn check_arch(elf_header: &Header) -> Result<(), &'static str> {
        let expect_arch = if cfg!(target_arch = "x86_64") {
            header::Machine::X86_64
        } else if cfg!(target_arch = "aarch64") {
            header::Machine::AArch64
        } else if cfg!(target_arch = "riscv64") {
            header::Machine::RISC_V
        } else if cfg!(target_arch = "loongarch64") {
            // https://github.com/loongson/la-abi-specs/blob/release/laelf.adoc
            header::Machine::Other(258)
        } else {
            return Err("Unsupported architecture!");
        };
        if elf_header.pt2.machine().as_machine() != expect_arch {
            error!(
                "Invalid ELF arch! expect: {:?}, got: {:?}",
                expect_arch,
                elf_header.pt2.machine().as_machine()
            );
            return Err("Invalid ELF arch!");
        }
        Ok(())
    }

    pub fn path(&self) -> String {
        self._elf.file_path.clone()
    }
}
pub struct ELFSegment {
    pub start_va: VirtAddr,
    pub size: usize,
    pub flags: MappingFlags,
    pub data: &'static [u8],
    pub offset: usize,
    pub type_: Type,
}

impl ELFSegment {
    pub fn into_to_mapping_flag(ph_flags: Flags) -> MappingFlags {
        let mut ret = MappingFlags::USER;
        if ph_flags.is_read() {
            ret |= MappingFlags::READ;
        }
        if ph_flags.is_write() {
            ret |= MappingFlags::WRITE;
        }
        if ph_flags.is_execute() {
            ret |= MappingFlags::EXECUTE;
        }
        ret
    }
}

/// 通过分析主程序和解释器的内存布局来确定安全的解释器基址
pub(crate) fn find_safe_base_address(prog_max: VirtAddr) -> VirtAddr {
    // 尝试在主程序之后找一个合适的位置
    let aligned_prog_max = prog_max.align_up_4k(); // 4KB页对齐
    let safe_base = aligned_prog_max + PAGE_SIZE_4K; // 额外增加4K间距

    safe_base
}

// 检查两个ELF信息的段是否有重叠
pub(crate) fn check_segments_overlap(interp_info: &ELFInfo, elf_info: &ELFInfo) -> bool {
    for i_seg in &interp_info.segments {
        if i_seg.type_ != xmas_elf::program::Type::Load {
            continue;
        }

        let i_start = i_seg.start_va;
        let i_end = i_start + i_seg.size;

        for m_seg in &elf_info.segments {
            if m_seg.type_ != xmas_elf::program::Type::Load {
                continue;
            }

            let m_start = m_seg.start_va;
            let m_end = m_start + m_seg.size;

            // 检查区间是否重叠
            if i_start < m_end && m_start < i_end {
                return true;
            }
        }
    }

    false
}
// 获取程序的地址范围
pub(crate) fn get_program_address_range(elf_file: &ElfFile) -> VirtAddrRange {
    let mut min_addr = usize::MAX;
    let mut max_addr = 0;

    for ph in elf_file.program_iter() {
        if let Ok(typ) = ph.get_type() {
            if typ == xmas_elf::program::Type::Load {
                let start = ph.virtual_addr() as usize;
                let end = start + ph.mem_size() as usize;

                if start < min_addr {
                    min_addr = start;
                }

                if end > max_addr {
                    max_addr = end;
                }
            }
        }
    }
    va_range!(min_addr..max_addr)
}
// 获取ELF文件的内存大小
pub(crate) fn get_elf_memory_size(elf_file: &ElfFile) -> (usize, usize) {
    let mut min_addr = usize::MAX;
    let mut max_addr = 0;

    for ph in elf_file.program_iter() {
        if let Ok(typ) = ph.get_type() {
            if typ == xmas_elf::program::Type::Load {
                let vaddr = ph.virtual_addr() as usize;
                let memsz = ph.mem_size() as usize;
                let end = vaddr + memsz;

                if vaddr < min_addr {
                    min_addr = vaddr;
                }
                if end > max_addr {
                    max_addr = end;
                }
            }
        }
    }

    (min_addr, max_addr - min_addr)
}
