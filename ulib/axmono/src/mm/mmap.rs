use core::ffi::{c_int, c_void};

use alloc::{
    sync::Arc,
    vec::{self, Vec},
};
use arceos_posix_api::{File, FileLike, ctypes, get_file_like, sys_lseek, sys_read};
use axerrno::{AxError, AxResult, LinuxResult, ax_err};
use axio::SeekFrom;
use axmm::{MmapFlags, MmapIO};
use axsync::Mutex;
use memory_addr::VirtAddr;
use spin::RwLock;

pub(crate) enum MmapResource {
    Anonymous,
    File(Arc<File>),
    FileLike(Arc<dyn FileLike>),
}

impl MmapResource {
    pub fn file(fd: c_int) -> LinuxResult<Self> {
        Ok(MmapResource::File(File::from_fd(fd)?))
    }
    pub fn file_like(fd: c_int) -> LinuxResult<Self> {
        Ok(MmapResource::FileLike(get_file_like(fd)?))
    }
}

pub(crate) struct MmapIOImpl {
    /// start of area
    pub base: RwLock<usize>,
    pub file_offset: usize,
    pub resource: MmapResource,
    pub flags: axmm::MmapFlags,
}

impl MmapIO for MmapIOImpl {
    fn set_base(&self, base: VirtAddr) {
        let mut base_ = self.base.write();
        *base_ = base.as_usize()
    }
    /// 参数
    ///   - start: 映射区的起始地址
    ///   - buf: 映射区的缓冲区
    fn read(&self, start: usize, buf: &mut [u8]) -> AxResult<usize> {
        let base = *self.base.read();
        let start = start - base + self.file_offset;
        debug!(
            "mmap read start=0x{:x} len={} with base=0x{:x} file_offset=0x{:x}",
            start,
            buf.len(),
            base,
            self.file_offset
        );
        match &self.resource {
            MmapResource::Anonymous => {
                debug!("mmap map anonymous");
                buf.fill(0);
                Ok(buf.len())
            }
            MmapResource::File(file) => {
                debug!("mmap read file at 0x{start:x}");
                warn!("{:?}", file.path());
                let mut file = file.inner().lock();
                let prev = file.seek(SeekFrom::Current(0))?;
                let result = file
                    .seek(SeekFrom::Start(start as u64))
                    .and_then(|_| file.read(buf));
                //debug!("mmap read buf = \n{:?}", buf);
                debug!("mmap read result={:?}", result);

                // recover cursor
                file.seek(SeekFrom::Start(prev))?;
                result
            }
            MmapResource::FileLike(_) => todo!(),
        }
    }

    fn write(&self, offset: usize, data: &[u8]) -> AxResult<usize> {
        // 根据 flags 处理写操作
        if self.flags.contains(MmapFlags::MAP_PRIVATE) {
            // 私有映射使用写时复制，不实际写入文件
            Ok(data.len())
        } else {
            match &self.resource {
                MmapResource::File(file) => {
                    let mut file = file.inner().lock();
                    let prev = file.seek(SeekFrom::Current(0))?;
                    let result = file
                        .seek(SeekFrom::Start((self.file_offset + offset) as u64))
                        .and(file.write(data));
                    // 恢复文件指针
                    file.seek(SeekFrom::Start(prev))?;
                    result
                }
                MmapResource::FileLike(_) => todo!(),
                MmapResource::Anonymous => Ok(data.len()),
            }
        }
    }

    fn flags(&self) -> axmm::MmapFlags {
        self.flags
    }
}
