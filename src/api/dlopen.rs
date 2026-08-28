use crate::{ElfLibrary, OpenFlags};
use alloc::boxed::Box;
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
/// `filename` follows the same requirements as [`dlopen`]. A null or unknown
/// `caller` falls back to the process-wide root search policy.
#[doc(hidden)]
pub unsafe extern "C" fn dlopen_with_caller(
    filename: *const c_char,
    flags: c_int,
    caller: *const c_void,
) -> *const c_void {
    let lib = if filename.is_null() {
        ElfLibrary::this()
    } else {
        let flags = OpenFlags::from_bits_retain(flags as _);
        let filename = unsafe { CStr::from_ptr(filename) };
        let Ok(path) = filename.to_str() else {
            return core::ptr::null();
        };
        let Ok(lib) = ElfLibrary::dlopen_from(path, flags, caller as usize) else {
            return core::ptr::null();
        };
        lib
    };
    Box::into_raw(Box::new(lib)) as _
}
