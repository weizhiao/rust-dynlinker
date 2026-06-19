use super::{
    stage0::AuxState,
    state::{BootstrapObject, BootstrapState},
};
use crate::globals::{
    __libc_enable_secure, _r_debug, EMPTY_NAME, MAIN_LINK_MAP, RTLD_NAME, RtldGlobalRoAux,
    publish_rtld_globals, rtld_link_map,
};
use core::{
    ffi::c_void,
    ptr::{addr_of_mut, null, null_mut},
};
use dlopen_rs::rtld::{
    debug::{LinkMap, RDebug, RT_CONSISTENT},
    elf::{ElfHeader, ElfPhdr},
};

struct RtldElfInfo {
    phdr: *const ElfPhdr,
    phnum: usize,
    entry: usize,
}

fn rtld_elf_info(load_bias: usize) -> RtldElfInfo {
    if load_bias == 0 {
        return RtldElfInfo {
            phdr: null(),
            phnum: 0,
            entry: 0,
        };
    }

    let ehdr = unsafe { core::ptr::read_unaligned(load_bias as *const ElfHeader) };
    if ehdr.e_phentsize() < core::mem::size_of::<ElfPhdr>() {
        return RtldElfInfo {
            phdr: null(),
            phnum: 0,
            entry: 0,
        };
    }

    RtldElfInfo {
        phdr: load_bias.wrapping_add(ehdr.e_phoff()) as *const ElfPhdr,
        phnum: ehdr.e_phnum(),
        entry: load_bias.wrapping_add(ehdr.e_entry()),
    }
}

pub(super) unsafe fn publish_bootstrap_objects(
    argc: usize,
    argv: *const *const u8,
    envp: *const *const u8,
    auxv: *const usize,
    aux: AuxState,
    main_load_bias: usize,
    main_dynamic: *const usize,
    rtld_load_bias: usize,
    rtld_dynamic: *const usize,
    exec_path: *const u8,
) -> BootstrapState {
    let main = addr_of_mut!(MAIN_LINK_MAP);
    let rtld = unsafe { rtld_link_map() };
    let rtld_info = rtld_elf_info(rtld_load_bias);

    unsafe {
        main.write(LinkMap {
            l_addr: main_load_bias as *mut c_void,
            l_name: EMPTY_NAME.as_ptr().cast(),
            l_ld: main_dynamic as *mut c_void,
            l_next: rtld,
            l_prev: null_mut(),
            l_real: main,
            l_phdr: aux.phdr as *const ElfPhdr,
            l_entry: aux.entry,
            l_phnum: aux.phnum as u16,
            ..LinkMap::zero()
        });
        rtld.write(LinkMap {
            l_addr: rtld_load_bias as *mut c_void,
            l_name: RTLD_NAME.as_ptr().cast(),
            l_ld: rtld_dynamic as *mut c_void,
            l_next: null_mut(),
            l_prev: main,
            l_real: rtld,
            l_phdr: rtld_info.phdr,
            l_entry: rtld_info.entry,
            l_phnum: rtld_info.phnum as u16,
            ..LinkMap::zero()
        });
        let r_debug = RDebug {
            version: 1,
            map: main,
            brk: Some(crate::symbols::_dl_debug_state),
            state: RT_CONSISTENT,
            ldbase: rtld_load_bias as *mut c_void,
        };
        addr_of_mut!(_r_debug).write(r_debug);
        publish_rtld_globals(
            main,
            rtld,
            r_debug,
            RtldGlobalRoAux {
                auxv,
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
            },
        );
        addr_of_mut!(__libc_enable_secure).write(if aux.secure == 0 { 0 } else { 1 });
    }

    BootstrapState {
        argc,
        argv,
        envp,
        auxv,
        exec_path,
        main: BootstrapObject {
            load_bias: main_load_bias,
            phdr: aux.phdr as *const ElfPhdr,
            phnum: aux.phnum,
            entry: aux.entry,
        },
        rtld: BootstrapObject {
            load_bias: rtld_load_bias,
            phdr: rtld_info.phdr.cast(),
            phnum: rtld_info.phnum,
            entry: rtld_info.entry,
        },
    }
}
