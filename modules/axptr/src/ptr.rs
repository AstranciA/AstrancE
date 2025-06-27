use axmm::AddrSpace;
use axhal::paging::MappingFlags;
use axerrno::{AxResult,AxError, ax_err};
use memory_addr::{VirtAddr, VirtAddrRange};
use core::slice;
use std::ffi::CStr;
use axerrno::LinuxError::{EACCES, EFAULT};

/// Validates a single pointer for memory safety in the given address space.
///
/// # Arguments
/// - `aspace`: Reference to the address space to check.
/// - `ptr`: The user-space pointer to validate.
/// - `size`: The size of the memory region pointed to.
/// - `write`: Whether write permissions are required (true) or read permissions are sufficient (false).
///
/// # Returns
/// - `AxResult<()>`: Ok if the pointer is valid and has appropriate permissions; otherwise, an error.
pub fn validate_ptr(
    aspace: &AddrSpace,
    ptr: *const u8,
    size: usize,
    write: bool,
) -> AxResult<()> {
    // Check for null pointer
    if ptr.is_null() {
        return ax_err!(InvalidInput, "Null pointer");
    }

    let start = VirtAddr::from_ptr_of(ptr);
    let range = VirtAddrRange::from_start_size(start, size);

    // Check if the range is within the address space
    if !aspace.contains_range(start, size) {
        return ax_err!(InvalidInput, "Pointer out of address space");
    }

    // Determine required permissions
    let access_flags = if write {
        MappingFlags::READ | MappingFlags::WRITE | MappingFlags::USER
    } else {
        MappingFlags::READ | MappingFlags::USER
    };

    // Check if the region is mapped with appropriate permissions
    if !aspace.check_region_access(range, access_flags) {
        return ax_err!(PermissionDenied, "Invalid memory access permissions");
    }

    Ok(())
}

/// Validates a slice for memory safety in the given address space.
///
/// # Arguments
/// - `aspace`: Reference to the address space to check.
/// - `slice`: The slice to validate.
/// - `write: bool`: Whether write permissions are required.
///
/// # Returns
/// - `AxResult<()>`: Ok if the slice is valid; otherwise, an error.
pub fn validate_slice<T>(
    aspace: &AddrSpace,
    slice: &[T],
    write: bool,
) -> AxResult<()> {
    validate_ptr(
        aspace,
        slice.as_ptr() as *const u8,
        core::mem::size_of_val(slice),
        write,
    )
}

/// Validates a mutable slice for memory safety in the given address space.
///
/// # Arguments
/// - `aspace`: Reference to the address space to check.
/// - `slice`: The mutable slice to validate.
///
/// # Returns
/// - `AxResult<()>`: Ok if the slice is valid for writing; otherwise, an error.
pub fn validate_slice_mut<T>(
    aspace: &AddrSpace,
    slice: &mut [T],
) -> AxResult<()> {
    validate_ptr(
        aspace,
        slice.as_ptr() as *const u8,
        core::mem::size_of_val(slice),
        true,
    )
}

/// Validates a C-style string pointer for memory safety.
///
/// # Arguments
/// - `aspace`: Reference to the address space to check.
/// - `c_str`: The C-string pointer to validate.
///
/// # Returns
/// - `AxResult<()>`: Ok if the string is valid and null-terminated; otherwise, an error.
pub fn validate_c_str(
    aspace: &AddrSpace,
    c_str: *const core::ffi::c_char,
) -> AxResult<()> {
    if c_str.is_null() {
        return ax_err!(InvalidInput, "Null C-string pointer");
    }

    let start = VirtAddr::from_ptr_of(c_str);
    if !aspace.contains(start) {
        return ax_err!(InvalidInput, "C-string pointer out of address space");
    }

    // Check for null terminator within a reasonable bound (e.g., page size)
    let max_len = axhal::mem::PAGE_SIZE_4K;
    let mut len = 0;
    let access_flags = MappingFlags::READ | MappingFlags::USER;

    while len < max_len {
        let addr = start + len;
        if !aspace.check_region_access(VirtAddrRange::from_start_size(addr, 1), access_flags) {
            return ax_err!(EFAULT, "Invalid C-string memory access");
        }

        let byte = unsafe { *(addr.as_ptr() as *const u8) };
        if byte == 0 {
            return Ok(());
        }
        len += 1;
    }

    ax_err!(InvalidInput, "C-string not null-terminated")
}

///safe functions for user
pub fn validated_user_slice<'a, T>(
    aspace: &AddrSpace,
    ptr: *const T,
    len: usize,
) -> AxResult<&'a [T]> {
    let size = len.checked_mul(core::mem::size_of::<T>()).ok_or_else(|| ax_err!(InvalidInput))?;
    validate_ptr(aspace, ptr as *const u8, size, false)?;
    Ok(unsafe { slice::from_raw_parts(ptr, len) })
}

pub fn validated_user_slice_mut<'a, T>(
    aspace: &AddrSpace,
    ptr: *mut T,
    len: usize,
) -> AxResult<&'a mut [T]> {
    let size = len.checked_mul(core::mem::size_of::<T>()).ok_or_else(|| ax_err!(InvalidInput))?;
    validate_ptr(aspace, ptr as *const u8, size, true)?;
    Ok(unsafe { slice::from_raw_parts_mut(ptr, len) })
}

pub fn validated_user_ptr<'a, T>(
    aspace: &AddrSpace,
    ptr: *const T,
    write: bool,
) -> AxResult<&'a T> {
    validate_ptr(aspace, ptr as *const u8, core::mem::size_of::<T>(), write)?;
    Ok(unsafe { &*ptr })
}

pub fn validated_user_ptr_mut<'a, T>(
    aspace: &AddrSpace,
    ptr: *mut T,
) -> AxResult<&'a mut T> {
    validate_ptr(aspace, ptr as *const u8, core::mem::size_of::<T>(), true)?;
    Ok(unsafe { &mut *ptr })
}

pub fn validated_user_cstr<'a>(
    aspace: &AddrSpace,
    ptr: *const core::ffi::c_char,
) -> AxResult<&'a CStr> {
    validate_c_str(aspace, ptr)?;
    Ok(unsafe { CStr::from_ptr(ptr) })
}

