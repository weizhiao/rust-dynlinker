use alloc::boxed::Box;

use super::stack::{AuxValues, ProcessStack};
use crate::globals::{
    __libc_enable_secure, _r_debug, RtldGlobalRoAux, publish_rtld_link_maps, publish_rtld_ro_aux,
};
use core::{
    ffi::c_void,
    ptr::{addr_of_mut, null, null_mut},
};
use dlopen_rs::rtld::{
    StartupState,
    debug::{RDebug, RT_CONSISTENT},
    elf::{ElfHeader, ElfPhdr},
    link_map::LinkMap,
};

#[derive(Copy, Clone)]
pub(super) struct BootstrapObject {
    pub(super) load_bias: usize,
    pub(super) phdr: *const ElfPhdr,
    pub(super) phnum: usize,
    pub(super) entry: usize,
}

#[derive(Copy, Clone)]
pub(super) struct BootstrapState {
    pub(super) process: ProcessStack,
    pub(super) main: BootstrapObject,
    pub(super) rtld: BootstrapObject,
}

fn rtld_object(load_bias: usize) -> BootstrapObject {
    if load_bias == 0 {
        return BootstrapObject {
            load_bias,
            phdr: null(),
            phnum: 0,
            entry: 0,
        };
    }

    let ehdr = unsafe { core::ptr::read_unaligned(load_bias as *const ElfHeader) };
    if ehdr.e_phentsize() < core::mem::size_of::<ElfPhdr>() {
        return BootstrapObject {
            load_bias,
            phdr: null(),
            phnum: 0,
            entry: 0,
        };
    }

    BootstrapObject {
        load_bias,
        phdr: load_bias.wrapping_add(ehdr.e_phoff()) as *const ElfPhdr,
        phnum: ehdr.e_phnum(),
        entry: load_bias.wrapping_add(ehdr.e_entry()),
    }
}

pub(super) unsafe fn publish_bootstrap_state(
    process: ProcessStack,
    aux: AuxValues,
    main_load_bias: usize,
    rtld_load_bias: usize,
) -> BootstrapState {
    unsafe {
        publish_rtld_ro_aux(RtldGlobalRoAux {
            auxv: process.auxv,
            platform: aux.platform as *const u8,
            pagesize: aux.pagesize,
            minsigstacksize: aux.minsigstacksize,
            clktck: aux.clktck,
            fpucw: aux.fpucw,
            hwcap: aux.hwcap,
            hwcap2: aux.hwcap2,
            hwcap3: aux.hwcap3,
            hwcap4: aux.hwcap4,
            sysinfo_ehdr: aux.sysinfo_ehdr,
        });
        addr_of_mut!(__libc_enable_secure).write(if aux.secure == 0 { 0 } else { 1 });
    }

    BootstrapState {
        process,
        main: BootstrapObject {
            load_bias: main_load_bias,
            phdr: aux.phdr as *const ElfPhdr,
            phnum: aux.phnum,
            entry: aux.entry,
        },
        rtld: rtld_object(rtld_load_bias),
    }
}

pub(super) unsafe fn publish_loaded_globals(
    state: &BootstrapState,
    main: *mut LinkMap,
    startup: StartupState,
) {
    let r_debug = RDebug {
        version: 1,
        map: main,
        brk: Some(crate::symbols::_dl_debug_state),
        state: RT_CONSISTENT,
        ldbase: state.rtld.load_bias as *mut c_void,
    };
    let libc_map = startup.libc_map;
    let initial_searchlist = Box::leak(startup.maps);
    let initial_searchlist_len = initial_searchlist.len();
    let initial_searchlist = initial_searchlist.as_mut_ptr();
    unsafe {
        link_loaded_objects(core::slice::from_raw_parts_mut(
            initial_searchlist,
            initial_searchlist_len,
        ));
        addr_of_mut!(_r_debug).write(r_debug);
        publish_rtld_link_maps(
            main,
            r_debug,
            initial_searchlist,
            initial_searchlist_len,
            libc_map,
        );
    }
}

unsafe fn link_loaded_objects(link_maps: &mut [*mut LinkMap]) {
    for index in 0..link_maps.len() {
        let link_map = link_maps[index];
        let prev = if index == 0 {
            null_mut()
        } else {
            link_maps[index - 1]
        };
        let next = link_maps.get(index + 1).copied().unwrap_or(null_mut());

        unsafe {
            (*link_map).l_prev = prev;
            (*link_map).l_next = next;
        }
    }
}
