use core::{
    ffi::{c_int, c_void},
    ptr::{addr_of_mut, null},
};
use dlopen_rs::rtld::{debug::RDebug, link_map::LinkMap};

pub(crate) use crate::glibc::RtldGlobalRoAux;
use crate::glibc::{RtldGlobal, RtldGlobalRo};

#[unsafe(no_mangle)]
pub static mut _dl_argv: *const *const u8 = null();

#[unsafe(no_mangle)]
pub static mut __libc_stack_end: *const usize = null();

#[unsafe(no_mangle)]
pub static mut _rtld_global: RtldGlobal = RtldGlobal::new();

#[unsafe(no_mangle)]
pub static mut _rtld_global_ro: RtldGlobalRo = RtldGlobalRo::new();

#[unsafe(no_mangle)]
pub static mut _r_debug: RDebug = RDebug::zero();

static mut RTLD_LINK_MAP: LinkMap = LinkMap::zero();

#[unsafe(no_mangle)]
pub static mut __libc_enable_secure: c_int = 0;

#[unsafe(no_mangle)]
pub static mut __rseq_flags: u32 = 0;

#[unsafe(no_mangle)]
pub static mut __rseq_size: u32 = 0;

#[unsafe(no_mangle)]
pub static mut __rseq_offset: isize = 0;

pub(crate) unsafe fn rtld_link_map() -> *mut LinkMap {
    addr_of_mut!(RTLD_LINK_MAP)
}

pub(crate) unsafe fn rtld_x86_cpu_features() -> *const c_void {
    unsafe { (&*addr_of_mut!(_rtld_global_ro)).x86_cpu_features() }
}

pub(crate) unsafe fn publish_rtld_ro_aux(ro_aux: RtldGlobalRoAux) {
    unsafe {
        (&mut *addr_of_mut!(_rtld_global_ro)).publish_aux(ro_aux);
    }
}

pub(crate) unsafe fn publish_rtld_link_maps(
    main: *mut LinkMap,
    r_debug: RDebug,
    initial_searchlist: *mut *mut LinkMap,
    initial_searchlist_len: usize,
    libc_map: *mut LinkMap,
) {
    unsafe {
        let global = &mut *addr_of_mut!(_rtld_global);
        let ro = &mut *addr_of_mut!(_rtld_global_ro);
        global.publish(
            main,
            ro.initial_searchlist(),
            r_debug,
            initial_searchlist_len,
            libc_map,
        );
        ro.publish_initial_searchlist(initial_searchlist, initial_searchlist_len);
    }
}

pub(crate) unsafe fn publish_tls_static_info(size: usize, align: usize) {
    unsafe {
        (&mut *addr_of_mut!(_rtld_global_ro)).publish_tls_static_info(size, align);
    }
}

pub(crate) unsafe fn publish_rseq_offset(offset: isize) {
    unsafe { addr_of_mut!(__rseq_offset).write(offset) };
}
