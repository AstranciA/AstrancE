pub mod mmap;
use core::arch::asm;

use alloc::string::String;
use alloc::vec::Vec;
use arceos_posix_api::{add_file_or_directory_fd, sys_open};
use axerrno::AxResult;
use axfs::api::{current_dir, write};
use axfs::fops::OpenOptions;
use axfs::path::join;
use axhal::trap::{PAGE_FAULT, register_trap_handler};
use axhal::{
    mem::{VirtAddr, virt_to_phys},
    paging::MappingFlags,
};
use axmm::AddrSpace;
use axtask::{TaskExtRef, current};
use kernel_elf_parser::{AuxvEntry, AuxvType};
use linux_raw_sys::general::{AT_ENTRY, AT_PHDR, AT_PHENT, AT_PHNUM};
use memory_addr::va;
use xmas_elf::ElfFile;

use crate::dynamic::{find_interpreter, load_interpreter, relocate_interpreter_segments};
use crate::elf::{check_segments_overlap, find_safe_base_address, get_program_address_range};
use crate::task::{self, read_trapframe_from_kstack};
use crate::{
    copy_from_kernel,
    elf::{ELFInfo, OwnedElfFile},
};

pub fn new_user_aspace_empty() -> AxResult<AddrSpace> {
    AddrSpace::new_empty(
        VirtAddr::from_usize(axconfig::plat::USER_SPACE_BASE),
        axconfig::plat::USER_SPACE_SIZE,
    )
}

/// load app to memory
/// # Returns
/// - The first return value is the entry point of the user app.
/// - The second return value is the top of the user stack.
/// - Third: thread pointer.
/// - The last return value is the address space of the user app.
pub fn load_elf_to_mem(
    elf_file: OwnedElfFile,
    uspace: &mut AddrSpace,
    args: Option<&[String]>,
    envs: Option<&[String]>,
) -> AxResult<(VirtAddr, VirtAddr, Option<VirtAddr>)> {
    // 检查是否需要动态链接器
    let interpreter_path = find_interpreter(&elf_file)?;

    // 如果有动态链接器，加载它
    if let Some(interp_path) = interpreter_path {
        let prog_max = get_program_address_range(&elf_file).end;
        //let interp_base = find_safe_base_address(prog_max);
        let interp_base = va!(axconfig::plat::USER_INTERP_BASE);
        // 加载主程序
        let elf_info = ELFInfo::new(elf_file, uspace.base(), Some(interp_base), None)?;
        // 加载解释器ELF文件
        let interpreter_elf = load_interpreter(&interp_path)?;
        //let mut interp_info = ELFInfo::new(interpreter_elf, uspace.base())?;
        let mut interp_info = ELFInfo::new(
            interpreter_elf,
            uspace.base(),
            None,
            Some(interp_base.as_usize() as isize),
        )?;

        /*
         *        // 检查解释器和主程序之间是否存在段重叠
         *        let is_overlapping = check_segments_overlap(&interp_info, &elf_info);
         *
         *        if is_overlapping {
         *            debug!("Detected overlap between interpreter and main program segments");
         *
         *            // 重定位解释器到一个安全的地址 (通常重定位到高地址)
         *            let safe_base = find_safe_base_address(&elf_info);
         *            relocate_interpreter_segments(&mut interp_info, safe_base);
         *            debug!("Relocated interpreter to base address {:#x}", safe_base);
         *        }
         */

        // 映射主程序段到内存
        debug!("mapping main elf");
        //map_elf_segments(&elf_info, uspace, &mut None)?;

        // 映射解释器段到内存，并获取其入口点
        debug!("mapping interp elf");
        let (interp_entry, ustack_pointer, tp) =
            map_elf_sections_with_auxv(interp_info, uspace, args, envs, &elf_info)?;

        // 返回解释器的入口点作为程序入口
        Ok((interp_entry, ustack_pointer, tp))
    } else {
        // 加载主程序
        let elf_info = ELFInfo::new(elf_file, uspace.base(), None, None)?;
        // 无需动态链接器，直接映射并返回
        let (entry, ustack_pointer, tp) = map_elf_sections(elf_info, uspace, args, envs)?;
        Ok((entry, ustack_pointer, tp))
    }
}

/// 设置用户栈并返回栈指针偏移
fn setup_user_stack(
    uspace: &mut AddrSpace,
    args: Option<&[String]>,
    envs: Option<&[String]>,
    auxv: &mut [AuxvEntry],
    ustack_start: VirtAddr,
    ustack_size: usize,
) -> Result<usize, axerrno::AxError> {
    debug!(
        "Mapping user stack: {:#x?}..{:#x?}",
        ustack_start,
        ustack_start + ustack_size
    );

    // 构建栈数据
    let stack_data = kernel_elf_parser::app_stack_region(
        args.unwrap_or_default(),
        envs.unwrap_or_default(),
        auxv,
        ustack_start,
        ustack_size,
    );
    //debug!("Stack data: {:?}", stack_data);

    // 映射栈空间
    uspace.map_alloc(
        ustack_start,
        ustack_size,
        MappingFlags::READ | MappingFlags::WRITE | MappingFlags::USER,
        true,
    )?;

    for au in auxv {
        let a_type = au.get_type();
        let a_val = au.value_mut_ref();
        match a_type {
            AuxvType::BASE=> {
                *a_val = 0x10000;
            }
            _ => {}
        }

        warn!("auxv: {} 0x{a_val:x?}", a_type as usize);
    }

    // 写入栈数据并返回偏移量
    let ustack_end = ustack_start + ustack_size;
    uspace.write(ustack_end - stack_data.len(), stack_data.as_slice())?;
    Ok(stack_data.len())
}

/// 映射ELF文件的段到地址空间
fn map_elf_segments(
    elf_info: &ELFInfo,
    uspace: &mut AddrSpace,
    tp: &mut Option<VirtAddr>,
) -> Result<(), axerrno::AxError> {
    for segment in elf_info.segments.iter() {
        match segment.type_ {
            xmas_elf::program::Type::Load => {
                let segment_end = segment.start_va + segment.size;
                trace!(
                    "Mapping ELF segment: [{:#x?}, {:#x?}) -> [{:#x?}, {:#x?}), flags: {:#x?}",
                    segment.start_va + segment.offset,
                    segment_end + segment.offset,
                    segment.start_va,
                    segment_end,
                    segment.flags
                );

                uspace.map_alloc(segment.start_va, segment.size, segment.flags, true)?;

                if !segment.data.is_empty() {
                    uspace.write(segment.start_va + segment.offset, segment.data)?;
                    uspace.fill_zero(
                        segment.start_va + segment.offset + segment.data.len(),
                        segment.size - segment.data.len(),
                    );
                }
                // TODO: flush the I-cache
            }
            xmas_elf::program::Type::Tls => {
                *tp = Some(segment.start_va + segment.offset);
            }
            _ => {
                panic!("Unsupported segment type");
            }
        }
    }
    Ok(())
}

/**
init stack with args, envs, argc and argv.
Returns:
- The entry point of the user app.
- The initial stack pointer
- The thread pointer
[argc | argv | env ]
^
sp
*/
pub fn map_elf_sections(
    mut elf_info: ELFInfo,
    uspace: &mut AddrSpace,
    args: Option<&[String]>,
    envs: Option<&[String]>,
) -> Result<(VirtAddr, VirtAddr, Option<VirtAddr>), axerrno::AxError> {
    let mut tp: Option<VirtAddr> = None;

    // 映射ELF段
    map_elf_segments(&elf_info, uspace, &mut tp)?;

    // 设置用户栈
    let ustack_end = VirtAddr::from_usize(axconfig::plat::USER_STACK_TOP);
    let ustack_size = axconfig::plat::USER_STACK_SIZE;
    let ustack_start = ustack_end - ustack_size;
    let sp_offset = setup_user_stack(
        uspace,
        args,
        envs,
        elf_info.auxv.as_mut_slice(),
        ustack_start,
        ustack_size,
    )?;

    // 映射陷入机制
    map_trampoline(uspace);

    // 初始化堆（如果启用）
    #[cfg(feature = "heap")]
    uspace.init_heap(
        axconfig::plat::USER_HEAP_BASE.into(),
        axconfig::plat::USER_HEAP_SIZE,
    );

    Ok((elf_info.entry, ustack_end - sp_offset, tp))
}

/// 映射ELF段并设置包含主程序信息的辅助向量
fn map_elf_sections_with_auxv(
    mut interp_info: ELFInfo,
    uspace: &mut AddrSpace,
    args: Option<&[String]>,
    envs: Option<&[String]>,
    main_elf_info: &ELFInfo,
) -> Result<(VirtAddr, VirtAddr, Option<VirtAddr>), axerrno::AxError> {
    let mut tp: Option<VirtAddr> = None;
    let mut args_ = vec![interp_info.path()];
    args.map(|args| {
        let path = if args[0].contains("/") {
            args[0].clone()
         } else {
            join(current_dir().unwrap().as_str(), &[args[0].as_str()])
        };
        args_.push(path);
        args_.extend_from_slice(&args[1..])
    });
    let mut envs_ = Vec::new();
    envs.map(|env| envs_.extend_from_slice(env));
    /*
     *    envs_.push("MUSL_DEBUG=2".into());
     *    envs_.push("LD_DEBUG=all".into());
     *    envs_.push("MUSL_DEBUGFLAGS=6".into());
     *
     */
    // 映射ELF段
    map_elf_segments(&interp_info, uspace, &mut tp)?;

    let path = interp_info.path();
    // 更新辅助向量，包含主程序信息
    for auxv in interp_info.auxv.iter_mut() {
        let a_type = auxv.get_type();
        let mut a_val = auxv.value_mut_ref();
        match a_type {
            /*
             *AuxvType::PHDR => {
             *    *a_val = main_elf_info.segments[0].start_va.as_usize()
             *        + main_elf_info
             *            .auxv
             *            .iter()
             *            .find(|a| a.get_type() == AuxvType::PHDR)
             *            .map_or(0, |a| a.value());
             *}
             *AuxvType::PHENT => {
             *    *a_val = main_elf_info
             *        .auxv
             *        .iter()
             *        .find(|a| a.get_type() == AuxvType::PHENT)
             *        .map_or(0, |a| a.value());
             *}
             *AuxvType::PHNUM => {
             *    *a_val = main_elf_info
             *        .auxv
             *        .iter()
             *        .find(|a| a.get_type() == AuxvType::PHNUM)
             *        .map_or(0, |a| a.value());
             *}
             *AuxvType::ENTRY => {
             *    *a_val = main_elf_info.entry.as_usize();
             *}
             */
            AuxvType::BASE => {
                warn!("base: {:?}", interp_info.base);
                *a_val = interp_info.base.as_usize();
            }
            /*
             *AuxvType::EXECFD => {
             *    let fd = add_file_or_directory_fd(
             *        axfs::fops::File::open,
             *        axfs::fops::Directory::open_dir,
             *        path.as_str(),
             *        &OpenOptions::new().set_read(true),
             *    ).unwrap();
             *    error!("execfd: {fd}");
             *    *a_val = fd as usize;
             *}
             * // FIXME:
             *AuxvType::EXECFN => {
             *}
             */
            _ => {}
        }
    }

    // 设置用户栈
    let ustack_end = VirtAddr::from_usize(axconfig::plat::USER_STACK_TOP);
    let ustack_size = axconfig::plat::USER_STACK_SIZE;
    let ustack_start = ustack_end - ustack_size;
    let mut auxv = Vec::from(interp_info.auxv);
    //auxv.push(AuxvEntry::new(AuxvType::NULL, 0));

    debug!("args: {args_:?} envs: {envs_:?}");
    let sp_offset = setup_user_stack(
        uspace,
        Some(args_.as_slice()),
        Some(envs_.as_slice()),
        auxv.as_mut_slice(),
        ustack_start,
        ustack_size,
    )?;
    for auxv in interp_info.auxv.iter_mut() {
        let a_type = auxv.get_type();
        let mut a_val = auxv.value_mut_ref();
    }

    // 映射跳板
    map_trampoline(uspace);

    // 初始化堆（如果启用）
    #[cfg(feature = "heap")]
    uspace.init_heap(
        axconfig::plat::USER_HEAP_BASE.into(),
        axconfig::plat::USER_HEAP_SIZE,
    );

    Ok((interp_info.entry, ustack_end - sp_offset, None))
}

unsafe extern "C" {
    fn _strampoline();
    fn _etrampoline();
}

pub(crate) fn map_trampoline(aspace: &mut AddrSpace) {
    aspace
        .map_linear(
            axconfig::plat::USER_TRAMPOLINE_BASE.into(),
            virt_to_phys((_strampoline as usize).into()),
            _etrampoline as usize - _strampoline as usize,
            MappingFlags::READ | MappingFlags::EXECUTE | MappingFlags::USER,
        )
        .unwrap();
}

pub unsafe fn trampoline_vaddr(fn_: usize) -> usize {
    assert!(
        fn_ >= _strampoline as usize && fn_ < _etrampoline as usize,
        "Invalid trampoline address"
    );

    fn_ - _strampoline as usize + axconfig::plat::USER_TRAMPOLINE_BASE
}

#[percpu::def_percpu]
static mut ACCESSING_USER_MEM: bool = false;

/// Enables scoped access into user memory, allowing page faults to occur inside
/// kernel.
pub fn access_user_memory<R>(f: impl FnOnce() -> R) -> R {
    ACCESSING_USER_MEM.with_current(|v| {
        *v = true;
        let result = f();
        *v = false;
        result
    })
}

/// Check if the current thread is accessing user memory.
pub fn is_accessing_user_memory() -> bool {
    ACCESSING_USER_MEM.read_current()
}
#[register_trap_handler(PAGE_FAULT)]
fn handle_page_fault(vaddr: VirtAddr, access_flags: MappingFlags, is_user: bool) -> bool {
    trace!(
        "Page fault at {:#x?}, flags: {:#x?}, is_user: {:?}",
        vaddr, access_flags, is_user
    );
    let current = current();
    let mut aspace = current.task_ext().process_data().aspace.lock();
    let result = aspace.handle_page_fault(vaddr, access_flags);
    if !result && is_user {
        error!(
            "Unhandled user page fault at {:#x?}, access_flags: {access_flags:?}",
            vaddr
        );
        if let Some(kstack) = current.get_kernel_stack_top() {
            debug!(
                "page fault user trap frame:\n{:#x?}",
                read_trapframe_from_kstack(kstack)
            );
        }
        // TODO: Send SIGSEGV
        drop(aspace);
        task::sys_exit(-139);
    }
    result
}
