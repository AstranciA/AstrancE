use alloc::format;
use alloc::sync::Arc;
use axfs_vfs::{VfsNodeType, VfsOps, VfsResult};
// use devfile::{DeviceNode,DiskFile};
use crate::dev::Disk;
use crate::fs;
use fs::extra;

#[cfg(feature = "devfs")]
pub(crate) fn devfs() -> Arc<fs::devfs::DeviceFileSystem> {
    // let null = fs::devfs::NullDev;
    // let zero = fs::devfs::ZeroDev;
    // let bar = fs::devfs::ZeroDev;

    let null = Arc::new(fs::devfs::NullDev);
    let zero = Arc::new(fs::devfs::ZeroDev);

    let devfs = fs::devfs::DeviceFileSystem::new();
    // let sda1_dir = devfs.mkdir("sda1");
    // devfs.add("null", Arc::new(null));
    // devfs.add("zero", Arc::new(zero));
    devfs.add("null", null.clone());
    devfs.add("zero", zero.clone());

    let shm = Arc::new(extra::devfs::shm::ShmDev::new());
    devfs.add("shm", shm);

    // devfs.register_device_by_name("sda1",8,0,fs).expect("No Device");
    // devfs.register_device(1, 3, null);
    // devfs.register_device(1, 5, zero);
    Arc::new(devfs)
}

#[cfg(feature = "ramfs")]
pub(crate) fn ramfs() -> Arc<fs::ramfs::RamFileSystem> {
    Arc::new(fs::ramfs::RamFileSystem::new())
}

#[cfg(feature = "procfs")]
pub(crate) fn procfs() -> VfsResult<Arc<fs::procfs::ProcFileSystem>> {
    /*
     *    let procfs = fs::ramfs::RamFileSystem::new();
     *    let proc_root = procfs.root_dir();
     *
     *    // Create /proc/sys/net/core/somaxconn
     *    proc_root.create("sys", VfsNodeType::Dir)?;
     *    proc_root.create("sys/net", VfsNodeType::Dir)?;
     *    proc_root.create("sys/net/core", VfsNodeType::Dir)?;
     *    proc_root.create("sys/net/core/somaxconn", VfsNodeType::File)?;
     *    let file_somaxconn = proc_root.clone().lookup("./sys/net/core/somaxconn")?;
     *    file_somaxconn.write_at(0, b"4096\n")?;
     *
     *    // Create /proc/sys/vm/overcommit_memory
     *    proc_root.create("sys/vm", VfsNodeType::Dir)?;
     *    proc_root.create("sys/vm/overcommit_memory", VfsNodeType::File)?;
     *    let file_over = proc_root.clone().lookup("./sys/vm/overcommit_memory")?;
     *    file_over.write_at(0, b"0\n")?;
     *
     *    // Create /proc/self/stat
     *    proc_root.create("self", VfsNodeType::Dir)?;
     *    proc_root.create("self/stat", VfsNodeType::File)?;
     */
    use fs::procfs::*;
    let procfs = ProcFileSystem::new();
    let proc_root = procfs.root_dir_node().clone();

    let proc_version_string = format!(
        "{} version {} ({}) (rustc {}) {}\n",
        axconfig::SYSNAME,      // "AstrancE"
        axconfig::RELEASE,      // "0.1.0-alpha"
        axconfig::SYSNAME,      // "builder@astrance.io"
        "rustc 1.86.0-nightly", // 这里可以硬编码或从构建脚本获取编译器版本
        axconfig::VERSION       // "#1 SMP PREEMPT_DYNAMIC"
    );

    proc_root.create_static_file("version", proc_version_string.as_bytes())?;
    proc_root.create_static_file("config.gz", &[])?;

    Ok(Arc::new(procfs))
}

#[cfg(feature = "sysfs")]
pub(crate) fn sysfs() -> VfsResult<Arc<fs::ramfs::RamFileSystem>> {
    let sysfs = fs::ramfs::RamFileSystem::new();
    let sys_root = sysfs.root_dir();

    // Create /sys/kernel/mm/transparent_hugepage/enabled
    sys_root.create("kernel", VfsNodeType::Dir)?;
    sys_root.create("kernel/mm", VfsNodeType::Dir)?;
    sys_root.create("kernel/mm/transparent_hugepage", VfsNodeType::Dir)?;
    sys_root.create("kernel/mm/transparent_hugepage/enabled", VfsNodeType::File)?;
    let file_hp = sys_root
        .clone()
        .lookup("./kernel/mm/transparent_hugepage/enabled")?;
    file_hp.write_at(0, b"always [madvise] never\n")?;

    // Create /sys/devices/system/clocksource/clocksource0/current_clocksource
    sys_root.create("devices", VfsNodeType::Dir)?;
    sys_root.create("devices/system", VfsNodeType::Dir)?;
    sys_root.create("devices/system/clocksource", VfsNodeType::Dir)?;
    sys_root.create("devices/system/clocksource/clocksource0", VfsNodeType::Dir)?;
    sys_root.create(
        "devices/system/clocksource/clocksource0/current_clocksource",
        VfsNodeType::File,
    )?;
    let file_cc = sys_root
        .clone()
        .lookup("devices/system/clocksource/clocksource0/current_clocksource")?;
    file_cc.write_at(0, b"tsc\n")?;

    Ok(Arc::new(sysfs))
}
