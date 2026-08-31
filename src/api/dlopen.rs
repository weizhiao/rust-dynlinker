use crate::{
    OpenFlags,
    api::dlerror,
    dlopen::{open_file, open_main},
    registry::register_handle,
};
use core::ffi::{CStr, c_char, c_int, c_void};

/// # Safety
/// It is the same as `dlopen`.
#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dlopen(_filename: *const c_char, _flags: c_int) -> *const c_void {
    core::arch::naked_asm!(
        "mov rdx, [rsp]",
        "jmp {}",
        sym dlopen_with_caller,
    );
}

/// # Safety
/// It is the same as `dlopen`.
#[cfg(target_arch = "aarch64")]
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dlopen(_filename: *const c_char, _flags: c_int) -> *const c_void {
    core::arch::naked_asm!(
        "mov x2, x30",
        "b {}",
        sym dlopen_with_caller,
    );
}

/// # Safety
/// It is the same as `dlopen`.
#[cfg(target_arch = "riscv64")]
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dlopen(_filename: *const c_char, _flags: c_int) -> *const c_void {
    core::arch::naked_asm!(
        "mv a2, ra",
        "tail {}",
        sym dlopen_with_caller,
    );
}

/// Calls `dlopen` on behalf of the module containing `caller`.
///
/// # Safety
/// `filename` follows the same requirements as [`dlopen`]. An unknown `caller`
/// falls back to the process-wide root search policy.
#[doc(hidden)]
pub unsafe extern "C" fn dlopen_with_caller(
    filename: *const c_char,
    flags: c_int,
    caller: *const c_void,
) -> *const c_void {
    dlerror::clear();
    let opened = if filename.is_null() {
        open_main()
    } else {
        let flags = OpenFlags::from_bits_retain(flags as _);
        let filename = unsafe { CStr::from_ptr(filename) };
        let Ok(path) = filename.to_str() else {
            dlerror::set("library name is not valid UTF-8");
            return core::ptr::null();
        };
        match open_file(path, flags, caller as usize) {
            Ok(opened) => opened,
            Err(error) => {
                dlerror::set(error);
                return core::ptr::null();
            }
        }
    };
    register_handle(opened) as _
}
