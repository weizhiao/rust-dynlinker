use crate::{abi::dladdr::CDlInfo, image::dladdr_raw};
use core::ffi::{c_int, c_void};

/// # Safety
/// It is the same as `dladdr`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dladdr(addr: *const c_void, info: *mut CDlInfo) -> c_int {
    unsafe { dladdr_raw(addr, info) }
}
