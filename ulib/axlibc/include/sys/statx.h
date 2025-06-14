#ifndef __SYS_STAT_H__
#define __SYS_STAT_H__

#include <sys/time.h>
#include <sys/types.h>

struct statx {
    uint32_t stx_mask;            /* Mask of requested fields */
    blksize_t stx_blksize;         /* Block size for filesystem I/O */
    uint64_t stx_attributes;      /* Extra file attribute indicators */
    nlink_t stx_nlink;           /* Number of hard links */
    uid_t stx_uid;             /* User ID of owner */
    gid_t stx_gid;             /* Group ID of owner */
    mode_t stx_mode;            /* File type and mode */
    ino_t stx_ino;             /* Inode number */
    off_t stx_size;            /* Total size in bytes */
    blkcnt_t stx_blocks;          /* Number of 512B blocks allocated */
    uint64_t stx_attributes_mask; /* Mask to show supported attributes */

    struct timespec stx_atime;  /* Last access */
    struct timespec stx_btime;  /* Creation time */
    struct timespec stx_ctime;  /* Last status change */
    struct timespec stx_mtime;  /* Last modification */

   uint32_t stx_rdev_major;      /* Major ID of device (if special file) */
   uint32_t stx_rdev_minor;      /* Minor ID */
   uint32_t stx_dev_major;       /* Major ID of device containing file */
   uint32_t stx_dev_minor;       /* Minor ID */

   uint64_t stx_mnt_id;          /* Mount ID */

   uint32_t stx_dio_mem_align;        /* Mem alignment for DIO */
   uint32_t stx_dio_offset_align;     /* Offset alignment for DIO */

   uint64_t stx_subvol;               /* Subvolume ID */

   uint32_t stx_atomic_write_unit_min;
   uint32_t stx_atomic_write_unit_max;
   uint32_t stx_atomic_write_segments_max;

   uint32_t stx_dio_read_offset_align;
};

#define stx_atime stx_atim.tv_sec
#define stx_btime stx_btim.tv_sec
#define stx_ctime stx_ctim.tv_sec
#define stx_mtime stx_mtim.tv_sec

#define S_IFMT 0170000

#define S_IFDIR  0040000
#define S_IFCHR  0020000
#define S_IFBLK  0060000
#define S_IFREG  0100000
#define S_IFIFO  0010000
#define S_IFLNK  0120000
#define S_IFSOCK 0140000

#define S_TYPEISMQ(buf)  0
#define S_TYPEISSEM(buf) 0
#define S_TYPEISSHM(buf) 0
#define S_TYPEISTMO(buf) 0

#define S_ISDIR(mode)  (((mode)&S_IFMT) == S_IFDIR)
#define S_ISCHR(mode)  (((mode)&S_IFMT) == S_IFCHR)
#define S_ISBLK(mode)  (((mode)&S_IFMT) == S_IFBLK)
#define S_ISREG(mode)  (((mode)&S_IFMT) == S_IFREG)
#define S_ISFIFO(mode) (((mode)&S_IFMT) == S_IFIFO)
#define S_ISLNK(mode)  (((mode)&S_IFMT) == S_IFLNK)
#define S_ISSOCK(mode) (((mode)&S_IFMT) == S_IFSOCK)

#ifndef S_IRUSR
#define S_ISUID 04000
#define S_ISGID 02000
#define S_ISVTX 01000
#define S_IRUSR 0400
#define S_IWUSR 0200
#define S_IXUSR 0100
#define S_IRWXU 0700
#define S_IRGRP 0040
#define S_IWGRP 0020
#define S_IXGRP 0010
#define S_IRWXG 0070
#define S_IROTH 0004
#define S_IWOTH 0002
#define S_IXOTH 0001
#define S_IRWXO 0007
#endif

/* statx flags and mask (you can expand this later) */
#define STATX_TYPE            0x00000001U
#define STATX_MODE            0x00000002U
#define STATX_NLINK           0x00000004U
#define STATX_UID             0x00000008U
#define STATX_GID             0x00000010U
#define STATX_ATIME           0x00000020U
#define STATX_MTIME           0x00000040U
#define STATX_CTIME           0x00000080U
#define STATX_INO             0x00000100U
#define STATX_SIZE            0x00000200U
#define STATX_BLOCKS          0x00000400U
#define STATX_BASIC_STATS     0x000007ffU

/* Function declaration for statx syscall */
int statx(int dirfd, const char *restrict pathname,
          int flags, unsigned int mask,
          struct statx *restrict statxbuf);
#endif /* __SYS_STAT_H__ */