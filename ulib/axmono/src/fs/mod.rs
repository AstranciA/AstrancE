// smaps.rs (或者您希望放置此逻辑的文件)

use alloc::{
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use axfs::{
    PROC_ROOT, VfsError, VfsResult,
    proc::{ProcDir, ProcDirGenerator, ProcEntry, ProcFileGenerator},
};
use axprocess::Process;
use axtask::{TaskExtRef, current};
use core::fmt::Write;
use memory_addr::PAGE_SIZE_4K;
use axalloc::global_allocator;
use axhal::mem::{memory_regions, MemRegionFlags};
use axmm::{backend::VmAreaType, MmapFlags};

use crate::task::{PROCESS_TABLE, ProcessData};

mod irqs;

/// 此函数在内部被文件生成器调用，它会一次性创建所有数据，
fn generate_smaps_content(process: Arc<Process>) -> VfsResult<String> {
    let aspace = process
        .data::<ProcessData>()
        .ok_or(VfsError::InvalidData)?
        .aspace
        .lock();
    let mut output = String::new();

    for area in aspace.areas.iter() {
        let stats = area.stat();

        // 使用 `?` 传播 `writeln!` 可能返回的 core::fmt::Error，
        // 将其映射到 VfsError::Io。
        writeln!(
            &mut output,
            "{:016x}-{:016x} {} {:08x} 00:00 0                          {}",
            area.start().as_usize(),
            area.end().as_usize(),
            area.flags(),
            0,
            0
        )
        .map_err(|_| VfsError::Io)?;

        writeln!(&mut output, "Size:           {:8} kB", stats.size / 1024)
            .map_err(|_| VfsError::Io)?;
        writeln!(&mut output, "Rss:            {:8} kB", stats.rss / 1024)
            .map_err(|_| VfsError::Io)?;
        // writeln!(&mut output, "Pss:            {:8} kB", stats.pss() / 1024).map_err(|_| VfsError::Io)?;
        // writeln!(&mut output, "Shared_Clean:   {:8} kB", stats.shared_clean() / 1024).map_err(|_| VfsError::Io)?;
        // writeln!(&mut output, "Shared_Dirty:   {:8} kB", stats.shared_dirty() / 1024).map_err(|_| VfsError::Io)?;
        // writeln!(&mut output, "Private_Clean:  {:8} kB", stats.private_clean() / 1024).map_err(|_| VfsError::Io)?;
        // writeln!(&mut output, "Private_Dirty:  {:8} kB", stats.private_dirty() / 1024).map_err(|_| VfsError::Io)?;
        // writeln!(&mut output, "Referenced:     {:8} kB", stats.referenced() / 1024).map_err(|_| VfsError::Io)?;
        // writeln!(&mut output, "Anonymous:      {:8} kB", stats.anonymous() / 1024).map_err(|_| VfsError::Io)?;
        writeln!(&mut output, "Swap:           {:8} kB", stats.swap / 1024)
            .map_err(|_| VfsError::Io)?;
        writeln!(&mut output, "").map_err(|_| VfsError::Io)?;
    }

    Ok(output)
}

/// 为特定进程创建一个流式的 smaps 文件生成器。
///
/// 这个函数返回一个闭包，该闭包符合 `ProcFileGenerator` 的签名，
/// 实现了按需读取文件内容的功能。
fn create_smaps_file_generator(process: Arc<Process>) -> Arc<ProcFileGenerator> {
    Arc::new(move |offset: u64, buf: &mut [u8]| -> VfsResult<usize> {
        // 1. 在需要时动态生成完整内容。
        let full_content = generate_smaps_content(process.clone())?;

        // 2. 计算要从完整内容中复制的数据范围。
        let start = offset as usize;
        if start >= full_content.len() {
            return Ok(0); // 偏移量超出文件末尾，没有数据可读。
        }

        let end = (start + buf.len()).min(full_content.len());
        let slice_to_copy = &full_content[start..end];

        // 3. 将数据片段复制到 VFS 提供的缓冲区中。
        buf[..slice_to_copy.len()].copy_from_slice(slice_to_copy.as_bytes());

        // 4. 返回实际复制的字节数。
        Ok(slice_to_copy.len())
    })
}

/// 创建一个目录生成器，用于在访问 /proc 时动态生成所有进程的目录。
fn create_pid_dir_generator() -> Arc<ProcDirGenerator> {
    Arc::new(|| {
        let process_table = PROCESS_TABLE.read();
        let mut entries = Vec::new();

        for (pid, process) in process_table.iter() {
            // 为每个 PID 创建一个新的 ProcDir 节点
            let pid_dir = ProcDir::new(None);

            // 为该 PID 的 smaps 文件创建类型安全的文件生成器
            let smaps_generator = create_smaps_file_generator(process.clone());
            pid_dir
                .create_dynamic_file("smaps", smaps_generator)
                .expect("Failed to create smaps file in a new proc dir");

            // TODO: 在这里为该 PID 添加其他文件，如 "cmdline", "status" 等。
            // let cmdline_generator = create_cmdline_file_generator(process.clone());
            // pid_dir.create_dynamic_file("cmdline", cmdline_generator).unwrap();
            pid_dir.create_static_file("stat", b"");

            // 将配置好的 PID 目录添加到要返回的条目列表中
            entries.push((pid.to_string(), ProcEntry::Dir(pid_dir)));
        }
        Ok(entries)
    })
}

/// 生成 /proc/meminfo 内容
fn generate_meminfo_content() -> VfsResult<String> {
    let mut output = String::new();

    // 统计物理内存总量和空闲量
    let mut mem_total = 0;
    let mut mem_free = 0;
    for region in memory_regions() {
        if region.flags.contains(MemRegionFlags::FREE) {
            mem_total += region.size;
            mem_free += region.size;
        } else {
            mem_total += region.size;
        }
    }

    // 统计各类型小页数量
    let mut normal_pages = 0;
    let mut heap_pages = 0;
    let mut stack_pages = 0;
    let mut mmap_anon_pages = 0;
    let mut mmap_file_pages = 0;
    let mut shm_pages = 0;
    let mut elf_pages = 0;
    let mut kernel_stack_bytes = 0;
    let mut page_table_bytes = 0;
    let mut process_count = 0;
    for (_pid, process) in PROCESS_TABLE.read().iter() {
        if let Some(proc_data) = process.data::<ProcessData>() {
            process_count += 1;
            let aspace = proc_data.aspace.lock();
            for area in aspace.areas.iter() {
                let npages = area.size() / PAGE_SIZE_4K;
                if let Some(vm_type) = area.backend().get_vm_type() {
                    match vm_type {
                        VmAreaType::Normal => normal_pages += npages,
                        VmAreaType::Heap => heap_pages += npages,
                        VmAreaType::Stack => stack_pages += npages,
                        VmAreaType::Mmap(mmapio) => {
                            // 这里简单判断匿名映射
                            if mmapio.flags().contains(MmapFlags::MAP_ANONYMOUS) { // MAP_ANONYMOUS
                                mmap_anon_pages += npages;
                            } else {
                                mmap_file_pages += npages;
                            }
                        },
                        VmAreaType::Shm(_) => shm_pages += npages,
                        VmAreaType::Elf => elf_pages += npages,
                    }
                }
            }
            // 估算每个进程的内核栈为16KB
            kernel_stack_bytes += 16 * 1024;
            // 页表大小暂时估算为每个进程16KB
            page_table_bytes += 16 * 1024;
        }
    }

    let page_size_kb = PAGE_SIZE_4K / 1024;
    let anon_pages_kb = (heap_pages + stack_pages + mmap_anon_pages) * page_size_kb;
    let mapped_kb = (mmap_file_pages + elf_pages + mmap_anon_pages) * page_size_kb;
    let shmem_kb = shm_pages * page_size_kb;
    let kernel_stack_kb = kernel_stack_bytes / 1024;
    let page_tables_kb = page_table_bytes / 1024;

    // 估算 MemAvailable
    let cached_kb = mem_total / 2 / 1024;
    let buffers_kb = 0;
    let sreclaimable_kb = 0;
    let mem_available_kb = (mem_free / 1024) + cached_kb + buffers_kb - sreclaimable_kb;
    let mem_available_kb = if mem_available_kb < 0 { 0 } else { mem_available_kb };

    // 其他字段
    let slab_kb = 0;
    let sreclaimable_kb_actual = 0;
    let sunreclaim_kb = 0;
    let commit_limit_kb = (mem_total / 1024);
    let committed_as_kb = anon_pages_kb + mapped_kb + kernel_stack_kb + page_tables_kb;

    writeln!(&mut output, "MemTotal:       {:8} kB", mem_total / 1024).map_err(|_| VfsError::Io)?;
    writeln!(&mut output, "MemFree:        {:8} kB", mem_free / 1024).map_err(|_| VfsError::Io)?;
    writeln!(&mut output, "MemAvailable:   {:8} kB", mem_available_kb).map_err(|_| VfsError::Io)?;
    writeln!(&mut output, "Buffers:        {:8} kB", buffers_kb).map_err(|_| VfsError::Io)?;
    writeln!(&mut output, "Cached:         {:8} kB", cached_kb).map_err(|_| VfsError::Io)?;
    writeln!(&mut output, "SwapCached:     {:8} kB", 0).map_err(|_| VfsError::Io)?;
    writeln!(&mut output, "Active:         {:8} kB", 0).map_err(|_| VfsError::Io)?;
    writeln!(&mut output, "Inactive:       {:8} kB", 0).map_err(|_| VfsError::Io)?;
    writeln!(&mut output, "Active(anon):   {:8} kB", 0).map_err(|_| VfsError::Io)?;
    writeln!(&mut output, "Inactive(anon): {:8} kB", 0).map_err(|_| VfsError::Io)?;
    writeln!(&mut output, "Active(file):   {:8} kB", 0).map_err(|_| VfsError::Io)?;
    writeln!(&mut output, "Inactive(file): {:8} kB", 0).map_err(|_| VfsError::Io)?;
    writeln!(&mut output, "Unevictable:    {:8} kB", 0).map_err(|_| VfsError::Io)?;
    writeln!(&mut output, "Mlocked:        {:8} kB", 0).map_err(|_| VfsError::Io)?;
    writeln!(&mut output, "SwapTotal:      {:8} kB", 0).map_err(|_| VfsError::Io)?;
    writeln!(&mut output, "SwapFree:       {:8} kB", 0).map_err(|_| VfsError::Io)?;
    writeln!(&mut output, "Zswap:          {:8} kB", 0).map_err(|_| VfsError::Io)?;
    writeln!(&mut output, "Zswapped:       {:8} kB", 0).map_err(|_| VfsError::Io)?;
    writeln!(&mut output, "Dirty:          {:8} kB", 0).map_err(|_| VfsError::Io)?;
    writeln!(&mut output, "Writeback:      {:8} kB", 0).map_err(|_| VfsError::Io)?;
    writeln!(&mut output, "AnonPages:      {:8} kB", anon_pages_kb).map_err(|_| VfsError::Io)?;
    writeln!(&mut output, "Mapped:         {:8} kB", mapped_kb).map_err(|_| VfsError::Io)?;
    writeln!(&mut output, "Shmem:          {:8} kB", shmem_kb).map_err(|_| VfsError::Io)?;
    writeln!(&mut output, "KReclaimable:   {:8} kB", sreclaimable_kb_actual).map_err(|_| VfsError::Io)?;
    writeln!(&mut output, "Slab:           {:8} kB", slab_kb).map_err(|_| VfsError::Io)?;
    writeln!(&mut output, "SReclaimable:   {:8} kB", sreclaimable_kb_actual).map_err(|_| VfsError::Io)?;
    writeln!(&mut output, "SUnreclaim:     {:8} kB", sunreclaim_kb).map_err(|_| VfsError::Io)?;
    writeln!(&mut output, "KernelStack:    {:8} kB", kernel_stack_kb).map_err(|_| VfsError::Io)?;
    writeln!(&mut output, "PageTables:     {:8} kB", page_tables_kb).map_err(|_| VfsError::Io)?;
    writeln!(&mut output, "SecPageTables:  {:8} kB", 0).map_err(|_| VfsError::Io)?;
    writeln!(&mut output, "NFS_Unstable:   {:8} kB", 0).map_err(|_| VfsError::Io)?;
    writeln!(&mut output, "Bounce:         {:8} kB", 0).map_err(|_| VfsError::Io)?;
    writeln!(&mut output, "WritebackTmp:   {:8} kB", 0).map_err(|_| VfsError::Io)?;
    writeln!(&mut output, "CommitLimit:    {:8} kB", commit_limit_kb).map_err(|_| VfsError::Io)?;
    writeln!(&mut output, "Committed_AS:   {:8} kB", committed_as_kb).map_err(|_| VfsError::Io)?;
    writeln!(&mut output, "VmallocTotal:   {:8} kB", 34359738367u64).map_err(|_| VfsError::Io)?;
    writeln!(&mut output, "VmallocUsed:    {:8} kB", 0).map_err(|_| VfsError::Io)?;
    writeln!(&mut output, "VmallocChunk:   {:8} kB", 0).map_err(|_| VfsError::Io)?;
    writeln!(&mut output, "Percpu:         {:8} kB", 0).map_err(|_| VfsError::Io)?;
    writeln!(&mut output, "HardwareCorrupted: {:8} kB", 0).map_err(|_| VfsError::Io)?;
    writeln!(&mut output, "AnonHugePages:  {:8} kB", 0).map_err(|_| VfsError::Io)?;
    writeln!(&mut output, "ShmemHugePages: {:8} kB", 0).map_err(|_| VfsError::Io)?;
    writeln!(&mut output, "ShmemPmdMapped: {:8} kB", 0).map_err(|_| VfsError::Io)?;
    writeln!(&mut output, "FileHugePages:  {:8} kB", 0).map_err(|_| VfsError::Io)?;
    writeln!(&mut output, "FilePmdMapped:  {:8} kB", 0).map_err(|_| VfsError::Io)?;
    writeln!(&mut output, "CmaTotal:       {:8} kB", 0).map_err(|_| VfsError::Io)?;
    writeln!(&mut output, "CmaFree:        {:8} kB", 0).map_err(|_| VfsError::Io)?;
    writeln!(&mut output, "Unaccepted:     {:8} kB", 0).map_err(|_| VfsError::Io)?;
    writeln!(&mut output, "Balloon:        {:8} kB", 0).map_err(|_| VfsError::Io)?;
    writeln!(&mut output, "HugePages_Total:{:8}", 0).map_err(|_| VfsError::Io)?;
    writeln!(&mut output, "HugePages_Free: {:8}", 0).map_err(|_| VfsError::Io)?;
    writeln!(&mut output, "HugePages_Rsvd: {:8}", 0).map_err(|_| VfsError::Io)?;
    writeln!(&mut output, "HugePages_Surp: {:8}", 0).map_err(|_| VfsError::Io)?;
    writeln!(&mut output, "Hugepagesize:   {:8} kB", 2048).map_err(|_| VfsError::Io)?;
    writeln!(&mut output, "Hugetlb:        {:8} kB", 0).map_err(|_| VfsError::Io)?;
    writeln!(&mut output, "DirectMap4k:    {:8} kB", mem_total / 4 / 1024).map_err(|_| VfsError::Io)?;
    writeln!(&mut output, "DirectMap2M:    {:8} kB", mem_total / 2 / 1024).map_err(|_| VfsError::Io)?;
    writeln!(&mut output, "DirectMap1G:    {:8} kB", mem_total / 8 / 1024).map_err(|_| VfsError::Io)?;

    Ok(output)
}

/// 创建 /proc/meminfo 文件生成器
fn create_meminfo_file_generator() -> Arc<ProcFileGenerator> {
    Arc::new(|offset: u64, buf: &mut [u8]| -> VfsResult<usize> {
        let full_content = generate_meminfo_content()?;
        let start = offset as usize;
        if start >= full_content.len() {
            return Ok(0);
        }
        let end = (start + buf.len()).min(full_content.len());
        let slice_to_copy = &full_content[start..end];
        buf[..slice_to_copy.len()].copy_from_slice(slice_to_copy.as_bytes());
        Ok(slice_to_copy.len())
    })
}

/// 预留：其他常见 /proc 文件生成器
/// 例如 /proc/uptime
fn generate_uptime_content() -> VfsResult<String> {
    // TODO: 获取系统启动到现在的秒数
    Ok("0.00 0.00\n".to_string())
}

fn create_uptime_file_generator() -> Arc<ProcFileGenerator> {
    Arc::new(|offset: u64, buf: &mut [u8]| -> VfsResult<usize> {
        let full_content = generate_uptime_content()?;
        let start = offset as usize;
        if start >= full_content.len() {
            return Ok(0);
        }
        let end = (start + buf.len()).min(full_content.len());
        let slice_to_copy = &full_content[start..end];
        buf[..slice_to_copy.len()].copy_from_slice(slice_to_copy.as_bytes());
        Ok(slice_to_copy.len())
    })
}

/// 例如 /proc/loadavg
fn generate_loadavg_content() -> VfsResult<String> {
    // TODO: 获取系统负载
    Ok("0.00 0.00 0.00 1/1 1\n".to_string())
}

fn create_loadavg_file_generator() -> Arc<ProcFileGenerator> {
    Arc::new(|offset: u64, buf: &mut [u8]| -> VfsResult<usize> {
        let full_content = generate_loadavg_content()?;
        let start = offset as usize;
        if start >= full_content.len() {
            return Ok(0);
        }
        let end = (start + buf.len()).min(full_content.len());
        let slice_to_copy = &full_content[start..end];
        buf[..slice_to_copy.len()].copy_from_slice(slice_to_copy.as_bytes());
        Ok(slice_to_copy.len())
    })
}

/// 初始化 procfs 的 smaps 相关功能。
///
/// 这个函数应该在内核初始化序列中被调用。
pub fn init_fs() -> VfsResult<()> {
    let proc_root = PROC_ROOT.clone();

    // 1. 为 /proc/[pid] 目录结构设置主生成器。
    let pid_generator = create_pid_dir_generator();
    proc_root.add_generator(pid_generator);

    // 2. 专门处理 /proc/self，它代表当前进程。
    let self_dir = proc_root.create_dir("self")?;

    // 为 /proc/self/smaps 创建一个特殊的、符合签名的文件生成器。
    let self_smaps_generator = Arc::new(|offset: u64, buf: &mut [u8]| -> VfsResult<usize> {
        let curr = current();
        let current_process = curr.task_ext().thread.process().clone();
        let full_content = generate_smaps_content(current_process)?;
        let start = offset as usize;
        if start >= full_content.len() {
            return Ok(0);
        }
        let end = (start + buf.len()).min(full_content.len());
        let slice_to_copy = &full_content[start..end];
        buf[..slice_to_copy.len()].copy_from_slice(slice_to_copy.as_bytes());
        Ok(slice_to_copy.len())
    });
    self_dir.create_dynamic_file("smaps", self_smaps_generator)?;

    // === /proc/meminfo ===
    proc_root.create_dynamic_file("meminfo", create_meminfo_file_generator())?;
    // === /proc/uptime ===
    proc_root.create_dynamic_file("uptime", create_uptime_file_generator())?;
    // === /proc/loadavg ===
    proc_root.create_dynamic_file("loadavg", create_loadavg_file_generator())?;
    proc_root.create_static_file("mounts", "".as_bytes())?;

    irqs::init_proc_interrupts();

    // TODO: 在这里为 /proc/self 添加其他文件，如 "cmdline", "status" 等。

    Ok(())
}
