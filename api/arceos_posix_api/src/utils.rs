#![allow(dead_code)]
#![allow(unused_macros)]

use alloc::vec::Vec;
use axerrno::{LinuxError, LinuxResult};
use core::ffi::{CStr, c_char};
use crate::ctypes::off_t;

/// Convert a C string to a Rust string
pub fn char_ptr_to_str<'a>(str: *const c_char) -> LinuxResult<&'a str> {
    if str.is_null() {
        Err(LinuxError::EFAULT)
    } else {
        let str = str as *const _;
        unsafe { CStr::from_ptr(str) }
            .to_str()
            .map_err(|_| LinuxError::EINVAL)
    }
}

/// Convert a C string vector to a Rust string
/// vector should be terminated by a null pointer
/// e.g. char* argv[]
pub fn str_vec_ptr_to_str<'a>(strv: *const *const c_char) -> LinuxResult<Vec<&'a str>> {
    let mut strs = Vec::new();
    let mut ptr = strv;
    while !(unsafe { *ptr }).is_null() {
        strs.push(char_ptr_to_str(unsafe { *ptr })?);
        ptr = ptr.wrapping_add(1);
    }
    Ok(strs)
}

/// Convert a Rust string to a C string
pub unsafe fn str_to_cstr(s: &str, buf: *mut c_char) -> usize {
    let len = s.len();
    let dst = unsafe { core::slice::from_raw_parts_mut(buf, len + 1) };
    let src = unsafe { core::slice::from_raw_parts(s.as_ptr() as *const c_char, len) };
    dst[..len].copy_from_slice(src);
    dst[len] = (b'\0') as c_char;
    len + 1
}

/*
todo：validate_ptr
*/
pub(crate) fn check_and_read_user_ptr(ptr: *mut off_t) -> Result<off_t, LinuxError> {
    // 检查用户态指针合法性，然后读取值
    if ptr.is_null() {
        return Err(LinuxError::EFAULT);
    }
    // validate_ptr(ptr as usize, core::mem::size_of::<off_t>(), AccessType::Read)?;
    unsafe { Ok(*ptr) }
}

pub(crate) fn write_back_user_ptr(ptr: *mut off_t, val: off_t) -> Result<(), LinuxError> {
    // validate_ptr(ptr as usize, core::mem::size_of::<off_t>(), AccessType::Write)?;
    unsafe {
        *ptr = val;
    }
    Ok(())
}

pub unsafe fn copy_to_user<T: Copy>(dst: *mut T, src: &T) -> Result<(), LinuxError> {
    if dst.is_null() {
        return Err(LinuxError::EFAULT);
    }
    // SAFETY: 调用者应保证 dst 指向合法用户地址
    unsafe {
        dst.write_volatile(*src);
    }
    Ok(())
}

pub unsafe fn copy_from_user<T: Copy>(dst: &mut T, src: *const T) -> Result<(), LinuxError> {
    if src.is_null() {
        return Err(LinuxError::EFAULT);
    }
    unsafe {
        *dst = src.read_volatile();
    }
    Ok(())
}

pub fn check_null_ptr<T>(ptr: *const T) -> LinuxResult {
    if ptr.is_null() {
        Err(LinuxError::EFAULT)
    } else {
        Ok(())
    }
}

pub fn check_null_mut_ptr<T>(ptr: *mut T) -> LinuxResult {
    if ptr.is_null() {
        Err(LinuxError::EFAULT)
    } else {
        Ok(())
    }
}

#[macro_export]
macro_rules! syscall_body {
    ($fn: ident, $($stmt: tt)*) => {{
        #[allow(clippy::redundant_closure_call)]
        let res = (|| -> axerrno::LinuxResult<_> { $($stmt)* })();
        match res {
            Ok(_) | Err(axerrno::LinuxError::EAGAIN) => debug!(concat!(stringify!($fn), " => {:?}"),  res),
            Err(_) => info!(concat!(stringify!($fn), " => {:?}"), res),
        }
        match res {
            Ok(v) => v as _,
            Err(e) => {
                -e.code() as _
            }
        }
    }};
}

#[macro_export]
macro_rules! syscall_body_no_debug {
    ($($stmt: tt)*) => {{
        #[allow(clippy::redundant_closure_call)]
        let res = (|| -> axerrno::LinuxResult<_> { $($stmt)* })();
        match res {
            Ok(v) => v as _,
            Err(e) => {
                -e.code() as _
            }
        }
    }};
}
