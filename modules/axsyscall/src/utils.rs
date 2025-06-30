use core::ffi::{CStr, c_char};

pub(crate) unsafe fn cstr_to_str<'a>(ptr: usize) -> Result<&'a str, core::str::Utf8Error> {
    unsafe { CStr::from_ptr(ptr as *const c_char).to_str() }
}
