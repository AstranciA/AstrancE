//! [ArceOS](https://github.com/arceos-org/arceos) filesystem module.
//!
//! It provides unified filesystem operations for various filesystems.
//!
//! # Cargo Features
//!
//! - `fatfs`: Use [FAT] as the main filesystem and mount it on `/`. This feature
//!    is **enabled** by default.
//! - `devfs`: Mount [`axfs_devfs::DeviceFileSystem`] on `/dev`. This feature is
//!    **enabled** by default.
//! - `ramfs`: Mount [`axfs_ramfs::RamFileSystem`] on `/tmp`. This feature is
//!    **enabled** by default.
//! - `myfs`: Allow users to define their custom filesystems to override the
//!    default. In this case, [`MyFileSystemIf`] is required to be implemented
//!    to create and initialize other filesystems. This feature is **disabled** by
//!    by default, but it will override other filesystem selection features if
//!    both are enabled.
//!
//! [FAT]: https://en.wikipedia.org/wiki/File_Allocation_Table
//! [`MyFileSystemIf`]: fops::MyFileSystemIf

#![cfg_attr(all(not(test), not(doc)), no_std)]
#![feature(doc_auto_cfg)]

#[macro_use]
extern crate log;
extern crate alloc;

mod dyn_fs;

use alloc::{
    collections::BTreeMap,
    format,
    string::{String, ToString},
    sync::Arc,
};
pub mod api;
mod blkdev;
mod dev;
pub mod fops;
pub mod fs;
mod mounts;
pub mod path;
pub mod root;
use api::create_dir;
use axsync::Mutex;
use lazyinit::LazyInit;
pub use root::{CURRENT_DIR, CURRENT_DIR_PATH, ROOT_DIR, PROC_ROOT};

pub use crate::dev::Disk;
use axdriver::{AxDeviceContainer, prelude::*};
pub use axfs_vfs::{VfsNodeOps, VfsOps, VfsNodeType, VfsResult, VfsError};
pub mod proc {
    pub use axfs_procfs::*;
}

lazy_static::lazy_static! {
    pub static ref DISKS: Mutex<BTreeMap<String, Disk>> = Mutex::new(BTreeMap::new());
}

/// 按字母递增的设备命名
fn get_device_name(index: u8) -> String {
    // 确保 index 在合理范围内 (0-25 对应 a-z)
    let c = b'a' + (index % 26);
    let mut name = String::with_capacity(3); // "vda" 是3字节
    name.push_str("vd");
    name.push(c as char);
    name
}

/// Initializes filesystems by block devices.
pub fn init_filesystems(mut blk_devs: AxDeviceContainer<AxBlockDevice>) {
    info!("Initialize filesystems...");
    let root = blk_devs
        .first()
        .expect("No block device found!")
        .device_name();
    info!("  use block device 0: {:?} as rootfs", root);
    let mut i = 0;
    let mut disks = DISKS.lock();
    while let Some(device) = blk_devs.take_one() {
        // TODO: better device_name
        let device_name = get_device_name(i);
        warn!(
            "Find block device: {} -> {}",
            device.device_name(),
            device_name
        );
        //let a = fs::lwext4_rust::Ext4FileSystem::new(Disk::new(device, 1, 0));
        disks.insert(device_name, Disk::new(device, 1, 0));
        i += 1;
    }
    info!("{} disks in total", disks.len());
    root::init_rootfs(disks.pop_last().expect("No block device found!").1);
    info!("Initialize device filesystems...");
}
