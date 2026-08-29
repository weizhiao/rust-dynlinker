//! c interface

mod dl_find_object;
pub(crate) mod dl_iterate_phdr;
pub(crate) mod dladdr;
mod dlopen;
pub mod dlsym;

use core::ffi::{c_int, c_void};

pub use self::dl_find_object::{dl_find_dso_for_object, dl_find_object};
pub use self::dl_iterate_phdr::dl_iterate_phdr;
pub use self::dladdr::{DlInfo, dladdr};
pub use self::dlopen::{dlopen, dlopen_with_caller};
pub use self::dlsym::dlsym;

/// # Safety
/// It is the same as `dlclose`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dlclose(handle: *const c_void) -> c_int {
    if handle.is_null() {
        return -1;
    }
    log::info!("dlclose: Closing handle [{handle:p}]");
    if crate::registry::release_handle(handle as usize) {
        0
    } else {
        -1
    }
}
