use core::ffi::CStr;

pub(crate) unsafe fn cstr_to_str<'a>(ptr: usize) -> Result<&'a str, core::str::Utf8Error> {
    unsafe { CStr::from_ptr(ptr as *const i8).to_str() }
}
