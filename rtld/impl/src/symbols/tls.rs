use core::{
    ffi::{c_int, c_void},
    ptr::null_mut,
};

use dlopen_rs::rtld::{TlsModuleId, link_map::LinkMap};

#[unsafe(no_mangle)]
pub extern "C" fn __tls_get_addr(index: *const usize) -> *mut c_void {
    crate::tls::get_addr(index.cast()).cast()
}

#[unsafe(no_mangle)]
pub extern "C" fn _dl_allocate_tls(storage: *mut c_void) -> *mut c_void {
    unsafe { crate::tls::allocate(storage) }
}

#[unsafe(no_mangle)]
pub extern "C" fn _dl_allocate_tls_init(storage: *mut c_void, _main_thread: bool) -> *mut c_void {
    unsafe { crate::tls::init(storage) }
}

#[unsafe(no_mangle)]
pub extern "C" fn _dl_deallocate_tls(storage: *mut c_void, dealloc_tcb: bool) {
    unsafe { crate::glibc::deallocate_tcb(storage.cast()) };
    unsafe { crate::tls::deallocate(storage, dealloc_tcb) };
}

#[unsafe(no_mangle)]
pub extern "C" fn _dl_get_tls_static_info(size: *mut usize, align: *mut usize) {
    let (tls_size, tls_align) = crate::tls::static_info();
    unsafe {
        if !size.is_null() {
            size.write(tls_size);
        }
        if !align.is_null() {
            align.write(tls_align);
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn __nptl_change_stack_perm(_stack: *mut c_void) -> c_int {
    0
}

pub(crate) extern "C" fn dl_tls_get_addr_soft(link_map: *mut LinkMap) -> *mut c_void {
    let Some(link_map) = (unsafe { link_map.as_ref() }) else {
        return null_mut();
    };
    crate::tls::get_addr_soft(TlsModuleId::new(link_map.l_tls_modid)).cast()
}
