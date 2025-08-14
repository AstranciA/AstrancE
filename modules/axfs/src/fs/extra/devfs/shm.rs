use alloc::{collections::BTreeMap, string::String, string::ToString, sync::Arc, vec::Vec};
use axerrno::ax_err;
use axfs_vfs::{VfsNodeAttr, VfsNodeAttrX, VfsNodeOps, VfsNodePerm, VfsNodeType, VfsResult};
use axmm::{
    FrameTrackerRef, IPC_CREAT, ShmSegment,
    shm::{ShmManager, create_new_shm_segment, posix::PosixShmManager},
};
use axsync::Mutex;
use memory_addr::FrameTracker;

pub struct ShmDevFileNode {
    name: String,
    shm_segment: Arc<Mutex<ShmSegment>>,
}

impl ShmDevFileNode {
    pub fn new(name: String, shm_segment: Arc<Mutex<ShmSegment>>) -> Arc<Self> {
        Arc::new(Self { name, shm_segment })
    }
}

impl VfsNodeOps for ShmDevFileNode {
    fn get_attr(&self) -> VfsResult<VfsNodeAttr> {
        let segment = self.shm_segment.lock();

        let inode_num = segment.id as u64;

        // Calculate blocks in 512-byte units, as is common for stat.
        // (size + 511) / 512
        let blocks_512_bytes = (segment.size as u64 + 511) / 512;

        Ok(VfsNodeAttr::new(
            0,                             // dev: Device ID, 0 for virtual file systems or not applicable
            VfsNodePerm::default_file(), // mode: Permissions (rw-rw-rw-)
            VfsNodeType::File,             // ty: Node type
            segment.size as u64,           // size: Current size of the segment
            blocks_512_bytes,              // blocks: Number of 512-byte blocks
            inode_num,                     // st_ino: Inode number
            1,                             // nlink: Hard links, typically 1 for a file
            0,                             // uid: User ID (root)
            0,                             // gid: Group ID (root)
            0,                             // nblk_lo: Custom field, setting to 0
            0,                             // atime: Access time (seconds)
            0,                             // ctime: Change time (seconds)
            0,                             // mtime: Modification time (seconds)
            0,                             // atime_nsec: Access time (nanoseconds)
            0,                             // mtime_nsec: Modification time (nanoseconds)
            0,                             // ctime_nsec: Change time (nanoseconds)
        ))
    }
    fn get_attr_x(&self) -> VfsResult<VfsNodeAttrX> {
        let segment = self.shm_segment.lock();

        let inode_num = segment.id as u64;

        // Calculate blocks in 512-byte units, as is common for stat.
        // (size + 511) / 512
        let blocks_512_bytes = (segment.size as u64 + 511) / 512;

        Ok(VfsNodeAttrX::new(
            0,
            0,
            0,
            0,
            0,
            0, // dev: Device ID, 0 for virtual file systems or not applicable
            VfsNodePerm::default_file(), // mode: Permissions (rw-rw-rw-)
            VfsNodeType::File, // ty: Node type
            segment.size as u64, // size: Current size of the segment
            blocks_512_bytes, // blocks: Number of 512-byte blocks
            inode_num, // st_ino: Inode number
            1, // nlink: Hard links, typically 1 for a file
            0, // uid: User ID (root)
            0, // gid: Group ID (root)
            0, // nblk_lo: Custom field, setting to 0
            0, // atime: Access time (seconds)
            0, // ctime: Change time (seconds)
            0, // mtime: Modification time (seconds)
            0, // atime_nsec: Access time (nanoseconds)
            0, // mtime_nsec: Modification time (nanoseconds)
            0, // ctime_nsec: Change time (nanoseconds)
            0,
            0,
            0,
        ))
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
        let shm_lock = self.shm_segment.lock();
        shm_lock.read_at(offset as usize, buf).into()
    }

    fn write_at(&self, offset: u64, buf: &[u8]) -> VfsResult<usize> {
        let mut shm_lock = self.shm_segment.lock();
        shm_lock.write_at(offset as usize, buf).into()
    }

    fn truncate(&self, size: u64) -> axfs_vfs::VfsResult {
        let mut shm_lock = self.shm_segment.lock();
        shm_lock.truncate(size as usize)
    }
}

pub struct ShmDev {
    manager: Mutex<PosixShmManager>,
}

impl ShmDev {
    pub fn new() -> Self {
        return Self {
            manager: Mutex::new(PosixShmManager::new()),
        };
    }
}

impl VfsNodeOps for ShmDev {
    fn get_attr(&self) -> VfsResult<VfsNodeAttr> {
        Ok(VfsNodeAttr::new(
            0,
            VfsNodePerm::default_dir(),
            VfsNodeType::Dir,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ))
    }

    fn get_attr_x(&self) -> VfsResult<VfsNodeAttrX> {
        Ok(VfsNodeAttrX::new(
            0,
            0,
            0,
            0,
            0,
            0,
            VfsNodePerm::default_dir(),
            VfsNodeType::CharDevice,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ))
    }

    fn lookup(self: Arc<Self>, path: &str) -> VfsResult<Arc<dyn VfsNodeOps>> {
        // For lookup, we don't want to create a new segment if it doesn't exist.
        // So, oflag should be 0 (no IPC_CREAT).
        let oflag = 0;
        let mode = 0; // Mode is irrelevant for lookup

        let shm_segment_arc = self
            .manager
            .lock()
            .get_or_create_shm_segment(path, oflag, mode)?;

        // If get_or_create_shm_segment returns Ok, it means the segment was found.
        let file_node = ShmDevFileNode::new(path.to_string(), shm_segment_arc);
        Ok(file_node)
    }

    fn create(&self, path: &str, ty: axfs_vfs::VfsNodeType) -> axfs_vfs::VfsResult {
        if ty != VfsNodeType::File {
            return ax_err!(Unsupported);
        }
        let mut manager = self.manager.lock();

        manager.get_or_create_shm_segment(path, IPC_CREAT, 0)?;
        Ok(())
    }

    fn remove(&self, path: &str) -> VfsResult {
        let mut manager = self.manager.lock();

        manager.unlink_shm_segment(path)?;
        Ok(())
    }

    fn read_dir(
        &self,
        start_idx: usize,
        dirents: &mut [axfs_vfs::VfsDirEntry],
    ) -> axfs_vfs::VfsResult<usize> {
        let mut manager = self.manager.lock();
        let dirs: Vec<axfs_vfs::VfsDirEntry> = manager
            .read_dir(start_idx, dirents.len())
            .iter()
            .map(|(name, _)| axfs_vfs::VfsDirEntry::new(name.as_str(), VfsNodeType::File))
            .collect();
        let n = dirs.len();
        if n > 0 {
            dirents[..n].copy_from_slice(dirs.as_slice())
        };
        Ok(n)
    }
}
