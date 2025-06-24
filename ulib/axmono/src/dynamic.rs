use core::{error, ffi::CStr};
use axfs::path::{base_name, join};
use axio::Read;
use memory_addr::VirtAddr;
use xmas_elf::program::SegmentData;

use crate::elf::{ELFInfo, OwnedElfFile};
use alloc::{string::String, vec::Vec};
use axerrno::{AxError, AxResult};

/// 从ELF文件中查找解释器路径
pub(crate) fn find_interpreter(elf: &OwnedElfFile) -> AxResult<Option<String>> {
    // 查找INTERP段
    if let Some(interp) = elf
        .program_iter()
        .find(|ph| ph.get_type() == Ok(xmas_elf::program::Type::Interp))
    {
        let data = match interp.get_data(&elf).unwrap() {
            SegmentData::Undefined(data) => data,
            _ => return Err(AxError::InvalidData),
        };

        // 解析路径字符串
        let mut path: String = CStr::from_bytes_until_nul(data)
            .map_err(|_| AxError::InvalidData)?
            .to_str()
            .map_err(|_| AxError::InvalidData)?
            .into();

        let interp_basename = base_name(path.as_str()).ok_or(AxError::InvalidInput)?;
        let interp_path = join(interp_basename.as_str(), &["/lib"]);

        info!("Found interpreter: {}, using {}", path, interp_path);
        Ok(Some(path))
    } else {
        // 没有解释器段，说明不是动态链接的可执行文件
        Ok(None)
    }
}

/// 加载解释器ELF文件
pub(crate) fn load_interpreter(path: &str) -> AxResult<OwnedElfFile> {
    // 从文件系统读取解释器文件
    let mut file = axfs::api::OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|_| {
            error!("Failed to open interpreter: {}", path);
            AxError::NotFound
        })?;

    // 读取文件内容
    let mut content = Vec::new();
    file.read_to_end(&mut content).map_err(|_| AxError::Io)?;

    // 解析为ELF文件
    OwnedElfFile::new(path, content)
}

// 重定位解释器的所有段
pub(crate) fn relocate_interpreter_segments(interp_info: &mut ELFInfo, new_base: VirtAddr) {
    // 计算需要移动的偏移量
    let mut min_addr = VirtAddr::from(usize::MAX);
    for seg in &interp_info.segments {
        if seg.type_ == xmas_elf::program::Type::Load && seg.start_va < min_addr {
            min_addr = seg.start_va;
        }
    }
    
    let offset = new_base - min_addr;
    
    // 调整所有段的地址
    for seg in &mut interp_info.segments {
        if seg.type_ == xmas_elf::program::Type::Load {
            seg.start_va += offset;
        }
    }
    warn!("base: {:?}, offset: 0x{offset:x}", interp_info.entry);
    // 调整入口点
    interp_info.entry += offset;
}
