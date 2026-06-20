use crate::arch::{
    DL_NNS, EXEC_PAGESIZE, FPU_DEFAULT, PTHREAD_MUTEX_RECURSIVE_NP, STDERR_FILENO,
    X86_CPU_FEATURES_SIZE,
};
use core::{
    ffi::{c_int, c_void},
    ptr::{addr_of, addr_of_mut, null, null_mut},
};
use dlopen_rs::rtld::{debug::RDebug, link_map::LinkMap};

mod tls;

pub(crate) use tls::{deallocate_tcb, dtv_value, init_tcb, set_dtv_value};

const RTLD_GLOBAL_SIZE: usize = 2120;
const RTLD_GLOBAL_RO_SIZE: usize = 928;
const LINK_NAMESPACE_SIZE: usize = 112;
const DEFAULT_STACK_PROT_FLAGS: c_int = 0x1 | 0x2;

#[derive(Clone, Copy)]
#[repr(C)]
pub(crate) struct RtldScopeElem {
    pub list: *mut *mut LinkMap,
    pub nlist: u32,
    pub _padding: u32,
}

impl RtldScopeElem {
    const ZERO: Self = Self {
        list: null_mut(),
        nlist: 0,
        _padding: 0,
    };
}

#[derive(Clone, Copy)]
#[repr(C)]
struct RtldList {
    next: *mut RtldList,
    prev: *mut RtldList,
}

impl RtldList {
    const ZERO: Self = Self {
        next: null_mut(),
        prev: null_mut(),
    };
}

#[derive(Clone, Copy)]
#[repr(C)]
struct RtldPthreadMutex {
    lock: c_int,
    count: u32,
    owner: c_int,
    nusers: u32,
    kind: c_int,
    spins: i16,
    elision: i16,
    list: RtldList,
}

impl RtldPthreadMutex {
    const RECURSIVE: Self = Self {
        lock: 0,
        count: 0,
        owner: 0,
        nusers: 0,
        kind: PTHREAD_MUTEX_RECURSIVE_NP,
        spins: 0,
        elision: 0,
        list: RtldList::ZERO,
    };
}

#[derive(Clone, Copy)]
#[repr(C)]
struct RtldRecursiveLock {
    mutex: RtldPthreadMutex,
}

impl RtldRecursiveLock {
    const RECURSIVE: Self = Self {
        mutex: RtldPthreadMutex::RECURSIVE,
    };
}

#[derive(Clone, Copy)]
#[repr(C)]
struct RtldUniqueSymTable {
    lock: RtldRecursiveLock,
    entries: *mut c_void,
    size: usize,
    n_elements: usize,
    free: *const c_void,
}

impl RtldUniqueSymTable {
    const ZERO: Self = Self {
        lock: RtldRecursiveLock::RECURSIVE,
        entries: null_mut(),
        size: 0,
        n_elements: 0,
        free: null(),
    };
}

#[derive(Clone, Copy)]
#[repr(C)]
struct RtldLinkNamespace {
    loaded: *mut LinkMap,
    nloaded: u32,
    _padding_after_nloaded: u32,
    main_searchlist: *mut RtldScopeElem,
    global_scope_alloc: u32,
    global_scope_pending_adds: u32,
    libc_map: *mut LinkMap,
    unique_sym_table: RtldUniqueSymTable,
}

impl RtldLinkNamespace {
    const ZERO: Self = Self {
        loaded: null_mut(),
        nloaded: 0,
        _padding_after_nloaded: 0,
        main_searchlist: null_mut(),
        global_scope_alloc: 0,
        global_scope_pending_adds: 0,
        libc_map: null_mut(),
        unique_sym_table: RtldUniqueSymTable::ZERO,
    };
}

#[derive(Clone, Copy)]
#[repr(C)]
struct RtldX86FeatureControl {
    bits: u32,
}

impl RtldX86FeatureControl {
    const DEFAULT: Self = Self { bits: 0 };
}

#[repr(C, align(8))]
pub(crate) struct RtldGlobal {
    dl_ns: [RtldLinkNamespace; DL_NNS],
    dl_nns: usize,
    dl_load_lock: RtldRecursiveLock,
    dl_load_write_lock: RtldRecursiveLock,
    dl_load_tls_lock: RtldRecursiveLock,
    dl_load_adds: u64,
    dl_initfirst: *mut LinkMap,
    dl_profile_map: *mut LinkMap,
    dl_num_relocations: usize,
    dl_num_cache_relocations: usize,
    dl_all_dirs: *mut c_void,
    dl_x86_feature_1: u32,
    dl_x86_feature_control: RtldX86FeatureControl,
    dl_stack_prot_flags: c_int,
    dl_tls_dtv_gaps: bool,
    _padding_after_tls_dtv_gaps: [u8; 3],
    dl_tls_max_dtv_idx: usize,
    dl_tls_dtv_slotinfo_list: *mut c_void,
    dl_tls_static_nelem: usize,
    dl_tls_static_used: usize,
    dl_tls_static_optional: usize,
    dl_initial_dtv: *mut c_void,
    dl_tls_generation: usize,
    dl_scope_free_list: *mut c_void,
    dl_stack_used: RtldList,
    dl_stack_user: RtldList,
    dl_stack_cache: RtldList,
    dl_stack_cache_actsize: usize,
    dl_in_flight_stack: usize,
    dl_stack_cache_lock: c_int,
    _tail_padding: u32,
}

impl RtldGlobal {
    pub(crate) const fn new() -> Self {
        Self {
            dl_ns: [RtldLinkNamespace::ZERO; DL_NNS],
            dl_nns: 1,
            dl_load_lock: RtldRecursiveLock::RECURSIVE,
            dl_load_write_lock: RtldRecursiveLock::RECURSIVE,
            dl_load_tls_lock: RtldRecursiveLock::RECURSIVE,
            dl_load_adds: 0,
            dl_initfirst: null_mut(),
            dl_profile_map: null_mut(),
            dl_num_relocations: 0,
            dl_num_cache_relocations: 0,
            dl_all_dirs: null_mut(),
            dl_x86_feature_1: 0,
            dl_x86_feature_control: RtldX86FeatureControl::DEFAULT,
            dl_stack_prot_flags: DEFAULT_STACK_PROT_FLAGS,
            dl_tls_dtv_gaps: false,
            _padding_after_tls_dtv_gaps: [0; 3],
            dl_tls_max_dtv_idx: 0,
            dl_tls_dtv_slotinfo_list: null_mut(),
            dl_tls_static_nelem: 0,
            dl_tls_static_used: 0,
            dl_tls_static_optional: 0,
            dl_initial_dtv: null_mut(),
            dl_tls_generation: 1,
            dl_scope_free_list: null_mut(),
            dl_stack_used: RtldList::ZERO,
            dl_stack_user: RtldList::ZERO,
            dl_stack_cache: RtldList::ZERO,
            dl_stack_cache_actsize: 0,
            dl_in_flight_stack: 0,
            dl_stack_cache_lock: 0,
            _tail_padding: 0,
        }
    }

    pub(crate) unsafe fn publish(
        &mut self,
        main: *mut LinkMap,
        main_searchlist: *mut RtldScopeElem,
        _r_debug: RDebug,
        nloaded: usize,
        libc_map: *mut LinkMap,
    ) {
        let nloaded = nloaded as u32;
        unsafe {
            addr_of_mut!(self.dl_nns).write(1);
            addr_of_mut!(self.dl_load_adds).write(nloaded as u64);
            addr_of_mut!(self.dl_ns[0].loaded).write(main);
            addr_of_mut!(self.dl_ns[0].nloaded).write(nloaded);
            addr_of_mut!(self.dl_ns[0].main_searchlist).write(main_searchlist);
            addr_of_mut!(self.dl_ns[0].libc_map).write(libc_map);
            init_list(addr_of_mut!(self.dl_stack_used));
            init_list(addr_of_mut!(self.dl_stack_user));
            init_list(addr_of_mut!(self.dl_stack_cache));
        }
    }
}

#[repr(C, align(8))]
pub(crate) struct RtldGlobalRo {
    dl_debug_mask: c_int,
    _padding_after_debug_mask: u32,
    dl_platform: *const u8,
    dl_platformlen: usize,
    dl_pagesize: usize,
    dl_minsigstacksize: usize,
    dl_inhibit_cache: c_int,
    _padding_after_inhibit_cache: u32,
    dl_initial_searchlist: RtldScopeElem,
    dl_clktck: c_int,
    dl_verbose: c_int,
    dl_debug_fd: c_int,
    dl_lazy: c_int,
    dl_bind_not: c_int,
    dl_dynamic_weak: c_int,
    dl_fpu_control: u16,
    _padding_after_fpu_control: [u8; 6],
    dl_hwcap: u64,
    dl_auxv: *const usize,
    dl_x86_cpu_features: [u8; X86_CPU_FEATURES_SIZE],
    dl_x86_tlsdesc_dynamic: *const c_void,
    dl_x86_64_runtime_resolve: *const c_void,
    dl_inhibit_rpath: *const u8,
    dl_origin_path: *const u8,
    dl_tls_static_size: usize,
    dl_tls_static_align: usize,
    dl_tls_static_surplus: usize,
    dl_profile: *const u8,
    dl_profile_output: *const u8,
    dl_init_all_dirs: *mut c_void,
    dl_sysinfo_dso: *const c_void,
    dl_sysinfo_map: *mut LinkMap,
    dl_vdso_clock_gettime64: *const c_void,
    dl_vdso_gettimeofday: *const c_void,
    dl_vdso_time: *const c_void,
    dl_vdso_getcpu: *const c_void,
    dl_vdso_clock_getres_time64: *const c_void,
    dl_vdso_getrandom: *const c_void,
    dl_hwcap2: u64,
    dl_hwcap3: u64,
    dl_hwcap4: u64,
    dl_dso_sort_algo: u32,
    _padding_after_dso_sort_algo: u32,
    dl_debug_printf: *const c_void,
    dl_mcount: *const c_void,
    dl_lookup_symbol_x: *const c_void,
    dl_open: *const c_void,
    dl_close: *const c_void,
    dl_catch_error: *const c_void,
    dl_error_free: *const c_void,
    dl_tls_get_addr_soft: *const c_void,
    dl_libc_freeres: *const c_void,
    dl_find_object: *const c_void,
    dl_readonly_area: *const c_void,
    dl_dlfcn_hook: *const c_void,
    dl_audit: *mut c_void,
    dl_naudit: u32,
    _tail_padding: u32,
}

impl RtldGlobalRo {
    pub(crate) const fn new() -> Self {
        Self {
            dl_debug_mask: 0,
            _padding_after_debug_mask: 0,
            dl_platform: null(),
            dl_platformlen: 0,
            dl_pagesize: EXEC_PAGESIZE,
            dl_minsigstacksize: 0,
            dl_inhibit_cache: 0,
            _padding_after_inhibit_cache: 0,
            dl_initial_searchlist: RtldScopeElem::ZERO,
            dl_clktck: 0,
            dl_verbose: 0,
            dl_debug_fd: STDERR_FILENO,
            dl_lazy: 1,
            dl_bind_not: 0,
            dl_dynamic_weak: 0,
            dl_fpu_control: FPU_DEFAULT,
            _padding_after_fpu_control: [0; 6],
            dl_hwcap: 0,
            dl_auxv: null(),
            dl_x86_cpu_features: [0; X86_CPU_FEATURES_SIZE],
            dl_x86_tlsdesc_dynamic: null(),
            dl_x86_64_runtime_resolve: null(),
            dl_inhibit_rpath: null(),
            dl_origin_path: null(),
            dl_tls_static_size: 0,
            dl_tls_static_align: 1,
            dl_tls_static_surplus: 0,
            dl_profile: null(),
            dl_profile_output: null(),
            dl_init_all_dirs: null_mut(),
            dl_sysinfo_dso: null(),
            dl_sysinfo_map: null_mut(),
            dl_vdso_clock_gettime64: null(),
            dl_vdso_gettimeofday: null(),
            dl_vdso_time: null(),
            dl_vdso_getcpu: null(),
            dl_vdso_clock_getres_time64: null(),
            dl_vdso_getrandom: null(),
            dl_hwcap2: 0,
            dl_hwcap3: 0,
            dl_hwcap4: 0,
            dl_dso_sort_algo: 0,
            _padding_after_dso_sort_algo: 0,
            dl_debug_printf: null(),
            dl_mcount: null(),
            dl_lookup_symbol_x: null(),
            dl_open: null(),
            dl_close: null(),
            dl_catch_error: null(),
            dl_error_free: null(),
            dl_tls_get_addr_soft: null(),
            dl_libc_freeres: null(),
            dl_find_object: null(),
            dl_readonly_area: null(),
            dl_dlfcn_hook: null(),
            dl_audit: null_mut(),
            dl_naudit: 0,
            _tail_padding: 0,
        }
    }

    pub(crate) fn initial_searchlist(&mut self) -> *mut RtldScopeElem {
        addr_of_mut!(self.dl_initial_searchlist)
    }

    pub(crate) fn x86_cpu_features(&self) -> *const c_void {
        addr_of!(self.dl_x86_cpu_features).cast()
    }

    pub(crate) unsafe fn publish_tls_static_info(&mut self, size: usize, align: usize) {
        unsafe {
            addr_of_mut!(self.dl_tls_static_size).write(size);
            addr_of_mut!(self.dl_tls_static_align).write(align.max(1));
        }
    }

    pub(crate) unsafe fn publish_aux(&mut self, ro_aux: RtldGlobalRoAux) {
        unsafe {
            self.publish_function_pointers();
            let pagesize = if ro_aux.pagesize == 0 {
                EXEC_PAGESIZE
            } else {
                ro_aux.pagesize
            };
            let fpucw = if ro_aux.fpucw == 0 {
                FPU_DEFAULT
            } else {
                ro_aux.fpucw as u16
            };
            addr_of_mut!(self.dl_platform).write(ro_aux.platform);
            addr_of_mut!(self.dl_platformlen).write(c_strlen(ro_aux.platform));
            addr_of_mut!(self.dl_pagesize).write(pagesize);
            addr_of_mut!(self.dl_minsigstacksize).write(ro_aux.minsigstacksize);
            addr_of_mut!(self.dl_clktck).write(ro_aux.clktck as c_int);
            addr_of_mut!(self.dl_fpu_control).write(fpucw);
            addr_of_mut!(self.dl_hwcap).write(ro_aux.hwcap as u64);
            addr_of_mut!(self.dl_auxv).write(ro_aux.auxv);
            addr_of_mut!(self.dl_sysinfo_dso).write(ro_aux.sysinfo_ehdr as *const c_void);
            addr_of_mut!(self.dl_sysinfo_map).write(null_mut());
            addr_of_mut!(self.dl_hwcap2).write(ro_aux.hwcap2 as u64);
            addr_of_mut!(self.dl_hwcap3).write(ro_aux.hwcap3 as u64);
            addr_of_mut!(self.dl_hwcap4).write(ro_aux.hwcap4 as u64);
            self.publish_x86_cpu_defaults();
        }
    }

    unsafe fn publish_function_pointers(&mut self) {
        unsafe {
            addr_of_mut!(self.dl_catch_error)
                .write(crate::symbols::dl_catch_error as *const c_void);
            addr_of_mut!(self.dl_error_free).write(crate::symbols::dl_error_free as *const c_void);
            addr_of_mut!(self.dl_tls_get_addr_soft)
                .write(crate::symbols::dl_tls_get_addr_soft as *const c_void);
            addr_of_mut!(self.dl_dlfcn_hook).write(crate::symbols::dlfcn_hook());
        }
    }

    pub(crate) unsafe fn publish_initial_searchlist(
        &mut self,
        initial_searchlist: *mut *mut LinkMap,
        nlist: usize,
    ) {
        unsafe {
            addr_of_mut!(self.dl_initial_searchlist).write(RtldScopeElem {
                list: initial_searchlist,
                nlist: nlist as u32,
                _padding: 0,
            });
        }
    }

    unsafe fn publish_x86_cpu_defaults(&mut self) {
        // glibc 2.39 IFUNC resolvers copy these cached thresholds out of
        // _rtld_global_ro before libc's early init runs.
        const DATA_CACHE_SIZE_OFFSET: usize = 0x1e0 - RTLD_GLOBAL_RO_X86_FEATURES_OFFSET;
        const SHARED_CACHE_SIZE_OFFSET: usize = 0x1e8 - RTLD_GLOBAL_RO_X86_FEATURES_OFFSET;
        const NON_TEMPORAL_THRESHOLD_OFFSET: usize = 0x1f0 - RTLD_GLOBAL_RO_X86_FEATURES_OFFSET;
        const REP_MOVSB_STOP_THRESHOLD_OFFSET: usize = 0x1f8 - RTLD_GLOBAL_RO_X86_FEATURES_OFFSET;
        const REP_MOVSB_THRESHOLD_OFFSET: usize = 0x200 - RTLD_GLOBAL_RO_X86_FEATURES_OFFSET;
        const AVX_FAST_UNALIGNED_LOAD_THRESHOLD_OFFSET: usize =
            0x208 - RTLD_GLOBAL_RO_X86_FEATURES_OFFSET;

        const DATA_CACHE_SIZE: usize = 32 * 1024;
        const SHARED_CACHE_SIZE: usize = 1024 * 1024;
        const SAFE_MEMCPY_THRESHOLD: usize = 1024 * 1024;

        unsafe {
            self.write_x86_cpu_usize(DATA_CACHE_SIZE_OFFSET, DATA_CACHE_SIZE);
            self.write_x86_cpu_usize(SHARED_CACHE_SIZE_OFFSET, SHARED_CACHE_SIZE);
            self.write_x86_cpu_usize(NON_TEMPORAL_THRESHOLD_OFFSET, SAFE_MEMCPY_THRESHOLD);
            self.write_x86_cpu_usize(REP_MOVSB_STOP_THRESHOLD_OFFSET, SAFE_MEMCPY_THRESHOLD);
            self.write_x86_cpu_usize(REP_MOVSB_THRESHOLD_OFFSET, SAFE_MEMCPY_THRESHOLD);
            self.write_x86_cpu_usize(
                AVX_FAST_UNALIGNED_LOAD_THRESHOLD_OFFSET,
                SAFE_MEMCPY_THRESHOLD,
            );
        }
    }

    unsafe fn write_x86_cpu_usize(&mut self, offset: usize, value: usize) {
        if offset + core::mem::size_of::<usize>() > X86_CPU_FEATURES_SIZE {
            return;
        }
        let ptr = unsafe {
            addr_of_mut!(self.dl_x86_cpu_features)
                .cast::<u8>()
                .add(offset)
                .cast::<usize>()
        };
        unsafe { ptr.write_unaligned(value) };
    }
}

#[derive(Clone, Copy)]
pub(crate) struct RtldGlobalRoAux {
    pub auxv: *const usize,
    pub platform: *const u8,
    pub pagesize: usize,
    pub minsigstacksize: usize,
    pub clktck: usize,
    pub fpucw: usize,
    pub hwcap: usize,
    pub hwcap2: usize,
    pub hwcap3: usize,
    pub hwcap4: usize,
    pub sysinfo_ehdr: usize,
}

const _: [(); RTLD_GLOBAL_SIZE] = [(); core::mem::size_of::<RtldGlobal>()];
const _: [(); RTLD_GLOBAL_RO_SIZE] = [(); core::mem::size_of::<RtldGlobalRo>()];
const _: [(); LINK_NAMESPACE_SIZE] = [(); core::mem::size_of::<RtldLinkNamespace>()];
const _: [(); 0] = [(); core::mem::offset_of!(RtldGlobal, dl_ns)];
const _: [(); 1792] = [(); core::mem::offset_of!(RtldGlobal, dl_nns)];
const _: [(); 1968] = [(); core::mem::offset_of!(RtldGlobal, dl_x86_feature_1)];
const _: [(); 1976] = [(); core::mem::offset_of!(RtldGlobal, dl_stack_prot_flags)];
const _: [(); 1984] = [(); core::mem::offset_of!(RtldGlobal, dl_tls_max_dtv_idx)];
const _: [(); 2024] = [(); core::mem::offset_of!(RtldGlobal, dl_initial_dtv)];
const _: [(); 2032] = [(); core::mem::offset_of!(RtldGlobal, dl_tls_generation)];
const _: [(); 2048] = [(); core::mem::offset_of!(RtldGlobal, dl_stack_used)];
const _: [(); 24] = [(); core::mem::offset_of!(RtldGlobalRo, dl_pagesize)];
const _: [(); 96] = [(); core::mem::offset_of!(RtldGlobalRo, dl_hwcap)];
const _: [(); 112] = [(); core::mem::offset_of!(RtldGlobalRo, dl_x86_cpu_features)];
const _: [(); 640] = [(); core::mem::offset_of!(RtldGlobalRo, dl_x86_tlsdesc_dynamic)];
const _: [(); 648] = [(); core::mem::offset_of!(RtldGlobalRo, dl_x86_64_runtime_resolve)];
const _: [(); 656] = [(); core::mem::offset_of!(RtldGlobalRo, dl_inhibit_rpath)];
const _: [(); 672] = [(); core::mem::offset_of!(RtldGlobalRo, dl_tls_static_size)];
const _: [(); 720] = [(); core::mem::offset_of!(RtldGlobalRo, dl_sysinfo_dso)];
const _: [(); 776] = [(); core::mem::offset_of!(RtldGlobalRo, dl_vdso_getrandom)];
const _: [(); 784] = [(); core::mem::offset_of!(RtldGlobalRo, dl_hwcap2)];
const _: [(); 888] = [(); core::mem::offset_of!(RtldGlobalRo, dl_find_object)];
const _: [(); 896] = [(); core::mem::offset_of!(RtldGlobalRo, dl_readonly_area)];
const _: [(); 904] = [(); core::mem::offset_of!(RtldGlobalRo, dl_dlfcn_hook)];
const RTLD_GLOBAL_RO_X86_FEATURES_OFFSET: usize =
    core::mem::offset_of!(RtldGlobalRo, dl_x86_cpu_features);

unsafe fn init_list(list: *mut RtldList) {
    unsafe {
        addr_of_mut!((*list).next).write(list);
        addr_of_mut!((*list).prev).write(list);
    }
}

unsafe fn c_strlen(ptr: *const u8) -> usize {
    if ptr.is_null() {
        return 0;
    }
    let mut len = 0usize;
    while unsafe { ptr.add(len).read() } != 0 {
        len = len.wrapping_add(1);
    }
    len
}
