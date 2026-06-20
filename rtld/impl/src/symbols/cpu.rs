use core::ffi::c_void;

use crate::globals::rtld_x86_cpu_features;

#[unsafe(no_mangle)]
pub extern "C" fn _dl_x86_get_cpu_features() -> *const c_void {
    unsafe { rtld_x86_cpu_features() }
}
