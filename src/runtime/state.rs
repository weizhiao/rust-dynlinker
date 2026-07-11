use core::ffi::c_char;

pub(crate) static mut ARGC: usize = 0;
pub(crate) static mut ARGV: *const *mut c_char = core::ptr::null();
pub(crate) static mut ENVP: *const *const c_char = core::ptr::null();
