use core::ffi::c_void;

#[unsafe(no_mangle)]
pub extern "C" fn _dl_audit_preinit(_link_map: *mut c_void) {}

#[unsafe(no_mangle)]
pub extern "C" fn _dl_audit_symbind_alt(
    _link_map: *mut c_void,
    _ref: *const c_void,
    _value: *mut *mut c_void,
    _result: *mut c_void,
) {
}
