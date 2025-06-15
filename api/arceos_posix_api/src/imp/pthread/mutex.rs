use crate::{ctypes, utils::check_null_mut_ptr};

use axerrno::LinuxResult;
use axsync::Mutex;

use core::ffi::c_int;
use core::mem::{ManuallyDrop, size_of};

/*
* WARN:
* TOOD:
 *static_assertions::const_assert_eq!(
 *    size_of::<ctypes::pthread_mutex_t>(),
 *    size_of::<PthreadMutex>()
 *);
 */

#[repr(C)]
pub struct PthreadMutex(Mutex<()>);

impl PthreadMutex {
    const fn new() -> Self {
        Self(Mutex::new(()))
    }

    fn lock(&self) -> LinuxResult {
        let _guard = ManuallyDrop::new(self.0.lock());
        Ok(())
    }

    fn unlock(&self) -> LinuxResult {
        unsafe { self.0.force_unlock() };
        Ok(())
    }
}

/// Initialize a mutex.
pub fn sys_pthread_mutex_init(
    mutex: *mut ctypes::pthread_mutex_t,
    _attr: *const ctypes::pthread_mutexattr_t,
) -> c_int {
    debug!("sys_pthread_mutex_init <= {:#x}", mutex as usize);
    syscall_body!(sys_pthread_mutex_init, {
        check_null_mut_ptr(mutex)?;
        // Ensure the size and alignment match
        if size_of::<ctypes::pthread_mutex_t>() != size_of::<PthreadMutex>() ||
           core::mem::align_of::<ctypes::pthread_mutex_t>() != core::mem::align_of::<PthreadMutex>() {
            error!("pthread_mutex_t size or alignment mismatch!");
            return Err(LinuxError::EINVAL); // Or a more appropriate error
        }
        unsafe {
            mutex.cast::<PthreadMutex>().write(PthreadMutex::new());
        }
        Ok(0)
    })
}

/// Lock the given mutex.
pub fn sys_pthread_mutex_lock(mutex: *mut ctypes::pthread_mutex_t) -> c_int {
    debug!("sys_pthread_mutex_lock <= {:#x}", mutex as usize);
    syscall_body!(sys_pthread_mutex_lock, {
        check_null_mut_ptr(mutex)?;
        // Ensure the size and alignment match
        if size_of::<ctypes::pthread_mutex_t>() != size_of::<PthreadMutex>() ||
           core::mem::align_of::<ctypes::pthread_mutex_t>() != core::mem::align_of::<PthreadMutex>() {
            error!("pthread_mutex_t size or alignment mismatch!");
            return Err(LinuxError::EINVAL); // Or a more appropriate error
        }
        unsafe {
            (*mutex.cast::<PthreadMutex>()).lock()?;
        }
        Ok(0)
    })
}

/// Unlock the given mutex.
pub fn sys_pthread_mutex_unlock(mutex: *mut ctypes::pthread_mutex_t) -> c_int {
    debug!("sys_pthread_mutex_unlock <= {:#x}", mutex as usize);
    syscall_body!(sys_pthread_mutex_unlock, {
        check_null_mut_ptr(mutex)?;
        // Ensure the size and alignment match
        if size_of::<ctypes::pthread_mutex_t>() != size_of::<PthreadMutex>() ||
           core::mem::align_of::<ctypes::pthread_mutex_t>() != core::mem::align_of::<PthreadMutex>() {
            error!("pthread_mutex_t size or alignment mismatch!");
            return Err(LinuxError::EINVAL); // Or a more appropriate error
        }
        unsafe {
            (*mutex.cast::<PthreadMutex>()).unlock()?;
        }
        Ok(0)
    })
}
