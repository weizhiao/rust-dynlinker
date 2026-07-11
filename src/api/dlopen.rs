use crate::{ElfLibrary, OpenFlags};
use alloc::boxed::Box;
use core::ffi::{CStr, c_char, c_int, c_void};

/// # Safety
/// It is the same as `dlopen`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dlopen(filename: *const c_char, flags: c_int) -> *const c_void {
    let lib = if filename.is_null() {
        ElfLibrary::this()
    } else {
        let flags = OpenFlags::from_bits_retain(flags as _);
        let filename = unsafe { CStr::from_ptr(filename) };
        let Ok(path) = filename.to_str() else {
            return core::ptr::null();
        };
        let Ok(lib) = ElfLibrary::dlopen(path, flags) else {
            return core::ptr::null();
        };
        lib
    };
    Box::into_raw(Box::new(lib)) as _
}
