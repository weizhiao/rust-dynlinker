#![allow(dead_code)]

pub mod auxv {
    pub const AT_NULL: usize = 0;
    pub const AT_PHDR: usize = 3;
    pub const AT_PHENT: usize = 4;
    pub const AT_PHNUM: usize = 5;
    pub const AT_PAGESZ: usize = 6;
    pub const AT_BASE: usize = 7;
    pub const AT_ENTRY: usize = 9;
    pub const AT_PLATFORM: usize = 15;
    pub const AT_HWCAP: usize = 16;
    pub const AT_CLKTCK: usize = 17;
    pub const AT_FPUCW: usize = 18;
    pub const AT_SECURE: usize = 23;
    pub const AT_RANDOM: usize = 25;
    pub const AT_HWCAP2: usize = 26;
    pub const AT_HWCAP3: usize = 29;
    pub const AT_HWCAP4: usize = 30;
    pub const AT_EXECFN: usize = 31;
    pub const AT_SYSINFO: usize = 32;
    pub const AT_SYSINFO_EHDR: usize = 33;
    pub const AT_MINSIGSTKSZ: usize = 51;
}

pub mod elf {
    #[allow(unused_imports)]
    pub use elf_loader::elf::{
        ElfDyn, ElfDynamicTag, ElfHeader, ElfPhdr, ElfProgramType, ElfRel, ElfRelType, ElfRela,
        ElfRelocationType, ElfRelr,
    };
    #[allow(unused_imports)]
    pub use elf_loader::{arch::NativeArch, relocation::RelocationArch};
}

pub mod memory {
    #[allow(unused_imports)]
    pub use elf_loader::{
        Result as ElfResult,
        memory::{ImageMemory, VmAddr, VmOffset},
    };
}

pub mod relocation {
    #[allow(unused_imports)]
    pub use elf_loader::relocation::{relocate_relative, relocate_relr};
}

pub mod link_map {
    use core::ffi::{c_char, c_void};

    use super::elf::ElfPhdr;

    #[derive(Debug, Clone, Copy)]
    #[repr(C)]
    pub struct LinkMap {
        pub l_addr: *mut c_void,
        pub l_name: *const c_char,
        pub l_ld: *mut c_void,
        pub l_next: *mut LinkMap,
        pub l_prev: *mut LinkMap,
        pub l_real: *mut LinkMap,
        pub l_ns: isize,
        pub l_libname: *mut c_void,
        pub l_info: [*mut c_void; 84],
        pub l_phdr: *const ElfPhdr,
        pub l_entry: usize,
        pub l_phnum: u16,
        pub l_ldnum: u16,
        pub _pad_after_ldnum: u32,
        pub _reserved_before_tls: [usize; 45],
        pub l_tls_initimage: *mut c_void,
        pub l_tls_initimage_size: usize,
        pub l_tls_blocksize: usize,
        pub l_tls_align: usize,
        pub l_tls_firstbyte_offset: usize,
        pub l_tls_offset: isize,
        pub l_tls_modid: usize,
        pub l_tls_dtor_count: usize,
        pub l_relro_addr: usize,
        pub l_relro_size: usize,
        pub l_serial: u64,
    }

    impl LinkMap {
        pub const fn zero() -> Self {
            Self {
                l_addr: core::ptr::null_mut(),
                l_name: core::ptr::null(),
                l_ld: core::ptr::null_mut(),
                l_next: core::ptr::null_mut(),
                l_prev: core::ptr::null_mut(),
                l_real: core::ptr::null_mut(),
                l_ns: 0,
                l_libname: core::ptr::null_mut(),
                l_info: [core::ptr::null_mut(); 84],
                l_phdr: core::ptr::null(),
                l_entry: 0,
                l_phnum: 0,
                l_ldnum: 0,
                _pad_after_ldnum: 0,
                _reserved_before_tls: [0; 45],
                l_tls_initimage: core::ptr::null_mut(),
                l_tls_initimage_size: 0,
                l_tls_blocksize: 0,
                l_tls_align: 0,
                l_tls_firstbyte_offset: 0,
                l_tls_offset: 0,
                l_tls_modid: 0,
                l_tls_dtor_count: 0,
                l_relro_addr: 0,
                l_relro_size: 0,
                l_serial: 0,
            }
        }
    }

    const _: [(); 1208] = [(); core::mem::size_of::<LinkMap>()];
    const _: [(); 1120] = [(); core::mem::offset_of!(LinkMap, l_tls_initimage)];
    const _: [(); 1160] = [(); core::mem::offset_of!(LinkMap, l_tls_offset)];
    const _: [(); 1168] = [(); core::mem::offset_of!(LinkMap, l_tls_modid)];

    unsafe impl Send for LinkMap {}
    unsafe impl Sync for LinkMap {}
}

pub mod debug {
    use core::ffi::{c_int, c_void};

    use super::link_map::LinkMap;

    pub const RT_CONSISTENT: c_int = 0;
    pub const RT_ADD: c_int = 1;
    pub const RT_DELETE: c_int = 2;

    #[derive(Clone, Copy)]
    #[repr(C)]
    pub struct RDebug {
        pub version: c_int,
        pub map: *mut LinkMap,
        pub brk: Option<extern "C" fn()>,
        pub state: c_int,
        pub ldbase: *mut c_void,
    }

    impl RDebug {
        pub const fn zero() -> Self {
            Self {
                version: 0,
                map: core::ptr::null_mut(),
                brk: None,
                state: RT_CONSISTENT,
                ldbase: core::ptr::null_mut(),
            }
        }
    }

    unsafe impl Send for RDebug {}
    unsafe impl Sync for RDebug {}
}
