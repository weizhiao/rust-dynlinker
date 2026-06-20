use core::ffi::{c_int, c_void};

#[unsafe(no_mangle)]
pub extern "C" fn _dl_find_dso_for_object(addr: *const c_void) -> *mut c_void {
    dlopen_rs::api::dl_find_dso_for_object(addr)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn _dl_find_object(pc: *const c_void, dlfo: *mut c_void) -> c_int {
    unsafe { dlopen_rs::api::dl_find_object(pc, dlfo) }
}
