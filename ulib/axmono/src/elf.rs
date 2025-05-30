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
use xmas_elf::program::Type;
use xmas_elf::{
    ElfFile,
    header::{self, Header},
    program::{Flags, ProgramHeader, SegmentData},
};

/*
 *const USPACE: [usize; 16 * 1024] = [0; 16 * 1024];
 *const USTACK: [usize; 4 * 1024] = [0; 4 * 1024];
 */

/// 持有ELF文件内容和解析结果的包装类型
pub struct OwnedElfFile {
    _content: Vec<u8>, // 保持所有权但不直接使用，下划线前缀表示这是一个仅用于所有权的字段
    elf_file: ElfFile<'static>, // 实际上这个'static引用指向_content
}
impl OwnedElfFile {
    pub fn new(content: Vec<u8>) -> AxResult<Self> {
        // 创建引用content的切片，但绕过生命周期检查
        // 安全性由结构体保证：elf_file不会比_content活得更久
        let slice = unsafe { core::slice::from_raw_parts(content.as_ptr(), content.len()) };
        let elf_file = ElfFile::new(slice).map_err(|_| AxError::InvalidData)?;
        Ok(Self {
            _content: content,
            elf_file,
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
    /// The entry point of the ELF file
    pub entry: VirtAddr,
    /// The segments of the ELF file
    pub segments: Vec<ELFSegment>,
    /// The auxiliary vectors of the ELF file
    pub auxv: [AuxvEntry; 16],

    _elf: OwnedElfFile,
}

impl ELFInfo {
    pub fn new(elf: OwnedElfFile, uspace_base: VirtAddr) -> Self {
        let elf_header = elf.header;

        // will be checked in parser
        //Self::assert_magic(&elf_header);

        Self::check_arch(&elf_header).unwrap();
        let elf_parser =
            kernel_elf_parser::ELFParser::new(&elf, 0, None, uspace_base.as_usize()).unwrap();

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

        info!("{:x}, {:x}", elf.header.pt2.entry_point(), elf_offset);
        ELFInfo {
            entry: VirtAddr::from(elf.header.pt2.entry_point() as usize + elf_offset),
            segments,
            auxv: elf_parser.auxv_vector(PAGE_SIZE_4K),
            _elf: elf,
        }
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
