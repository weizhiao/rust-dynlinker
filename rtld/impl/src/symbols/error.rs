use core::{
    ffi::{c_char, c_int, c_void},
    ptr::{null, null_mut},
};

use crate::runtime::{RTLD_FATAL_EXIT_STATUS, exit};

#[unsafe(no_mangle)]
pub extern "C" fn _dl_signal_error(
    _errcode: c_int,
    _objname: *const c_char,
    _occasion: *const c_char,
    _errstring: *const c_char,
) -> ! {
    exit(RTLD_FATAL_EXIT_STATUS)
}

#[unsafe(no_mangle)]
pub extern "C" fn _dl_signal_exception(
    _errcode: c_int,
    _exception: *const DlException,
    _occasion: *const c_char,
) -> ! {
    exit(RTLD_FATAL_EXIT_STATUS)
}

pub(crate) unsafe extern "C" fn dl_catch_error(
    objname: *mut *const c_char,
    errstring: *mut *const c_char,
    mallocedp: *mut bool,
    operate: Option<unsafe extern "C" fn(*mut c_void)>,
    args: *mut c_void,
) -> c_int {
    if let Some(operate) = operate {
        unsafe { operate(args) };
    }
    unsafe {
        if !objname.is_null() {
            objname.write(null());
        }
        if !errstring.is_null() {
            errstring.write(null());
        }
        if !mallocedp.is_null() {
            mallocedp.write(false);
        }
    }
    0
}

pub(crate) extern "C" fn dl_error_free(_ptr: *mut c_void) {}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn _dl_catch_exception(
    _exception: *mut DlException,
    operate: Option<unsafe extern "C" fn(*mut c_void)>,
    args: *mut c_void,
) -> c_int {
    if let Some(operate) = operate {
        unsafe { operate(args) };
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn _dl_exception_free(exception: *mut DlException) {
    if !exception.is_null() {
        unsafe {
            (*exception).objname = null();
            (*exception).errstring = null();
            (*exception).message_buffer = null_mut();
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _dl_exception_create(
    exception: *mut DlException,
    objname: *const c_char,
    errstring: *const c_char,
) {
    if !exception.is_null() {
        unsafe {
            (*exception).objname = objname;
            (*exception).errstring = errstring;
            (*exception).message_buffer = null_mut();
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _dl_exception_create_format(
    exception: *mut DlException,
    objname: *const c_char,
    fmt: *const c_char,
) {
    _dl_exception_create(exception, objname, fmt);
}

#[unsafe(no_mangle)]
pub extern "C" fn _dl_fatal_printf() -> ! {
    exit(RTLD_FATAL_EXIT_STATUS)
}

#[repr(C)]
pub struct DlException {
    objname: *const c_char,
    errstring: *const c_char,
    message_buffer: *mut c_void,
}
