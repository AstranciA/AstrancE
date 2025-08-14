/*
 *cfg_if::cfg_if! {
 *    if #[cfg(feature = "myfs")] {
 *        pub mod myfs;
 *    } else if #[cfg(feature = "lwext4_rs")] {
 *        pub mod lwext4_rust;
 *    } else if #[cfg(feature = "fatfs")] {
 *        pub mod fatfs;
 *    }
 *
 *}
 */
pub mod extra;

#[cfg(feature = "fatfs")]
pub mod fatfs;
#[cfg(feature = "lwext4_rs")]
pub mod lwext4_rust;
#[cfg(feature = "myfs")]
pub mod myfs;

#[cfg(feature = "devfs")]
pub use axfs_devfs as devfs;

#[cfg(feature = "ramfs")]
pub use axfs_ramfs as ramfs;

#[cfg(feature = "procfs")]
pub use axfs_procfs as procfs;
