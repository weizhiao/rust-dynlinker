use crate::{
    Result, Symbol,
    api::dlerror,
    error::find_symbol_error,
    registry::{global_find, handle_find, next_find},
};
use core::{
    ffi::{CStr, c_char, c_void},
    ptr::null,
};

/// # Safety
/// It is the same as `dlsym`.
#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dlsym(
    _handle: *const c_void,
    _symbol_name: *const c_char,
) -> *const c_void {
    core::arch::naked_asm!(
        "mov rdx, [rsp]",
        "jmp {}",
        sym dlsym_with_caller,
    );
}

/// # Safety
/// It is the same as `dlsym`.
#[cfg(target_arch = "aarch64")]
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dlsym(
    _handle: *const c_void,
    _symbol_name: *const c_char,
) -> *const c_void {
    core::arch::naked_asm!(
        "mov x2, x30",
        "b {}",
        sym dlsym_with_caller,
    );
}

/// # Safety
/// It is the same as `dlsym`.
#[cfg(target_arch = "riscv64")]
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dlsym(
    _handle: *const c_void,
    _symbol_name: *const c_char,
) -> *const c_void {
    core::arch::naked_asm!(
        "mv a2, ra",
        "tail {}",
        sym dlsym_with_caller,
    );
}

/// Calls `dlsym` on behalf of the module containing `caller`.
///
/// # Safety
/// `handle` and `symbol_name` follow the same requirements as [`dlsym`].
#[doc(hidden)]
pub unsafe extern "C" fn dlsym_with_caller(
    handle: *const c_void,
    symbol_name: *const c_char,
    caller: *const c_void,
) -> *const c_void {
    const RTLD_DEFAULT: usize = 0;
    const RTLD_NEXT: usize = usize::MAX;
    dlerror::clear();
    if symbol_name.is_null() {
        dlerror::set("symbol name is null");
        return null();
    }
    let value = handle as usize;
    let name = match unsafe { CStr::from_ptr(symbol_name).to_str() } {
        Ok(name) => name,
        Err(_) => {
            dlerror::set("symbol name is not valid UTF-8");
            return null();
        }
    };

    let sym = if value == RTLD_DEFAULT {
        log::info!("dlsym: Use RTLD_DEFAULT flag to find symbol [{}]", name);
        dlsym_default::<()>(name)
    } else if value == RTLD_NEXT {
        log::info!("dlsym: Use RTLD_NEXT flag to find symbol [{}]", name);
        unsafe { dlsym_next::<()>(caller as usize, name) }
    } else {
        unsafe { handle_find::<()>(value, name) }
            .ok_or_else(|| find_symbol_error(alloc::format!("can not find symbol:{name}")))
    };
    match sym {
        Ok(sym) => sym.into_raw().cast(),
        Err(error) => {
            dlerror::set(error);
            null()
        }
    }
}

/// Find a symbol in the global search scope.
#[inline]
pub fn dlsym_default<T>(name: &str) -> Result<Symbol<'static, T>> {
    unsafe { global_find(name) }
        .ok_or_else(|| find_symbol_error(alloc::format!("can not find symbol:{}", name)))
}

/// Find the next occurrence of a symbol after the module containing `caller`.
///
/// # Safety
/// `caller` must be an address in the calling module.
pub unsafe fn dlsym_next<T>(caller: usize, name: &str) -> Result<Symbol<'static, T>> {
    unsafe { next_find(caller, name) }
        .ok_or_else(|| find_symbol_error(alloc::format!("can not find symbol:{}", name)))
}
