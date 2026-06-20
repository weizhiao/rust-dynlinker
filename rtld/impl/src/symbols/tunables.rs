use core::ffi::c_void;

#[unsafe(no_mangle)]
pub extern "C" fn __tunable_is_initialized(_id: usize) -> bool {
    false
}

#[unsafe(no_mangle)]
pub extern "C" fn __tunable_get_val(id: usize, value: *mut c_void, _callback: *mut c_void) {
    if value.is_null() {
        return;
    }

    let Some(default) = TUNABLE_DEFAULTS.get(id) else {
        return;
    };

    unsafe {
        match *default {
            TunableDefault::I32(default) => value.cast::<i32>().write(default),
            TunableDefault::Usize(default) => value.cast::<usize>().write(default),
            TunableDefault::String(default) => value.cast::<*const TunableString>().write(default),
        }
    }
}

#[derive(Clone, Copy)]
enum TunableDefault {
    I32(i32),
    Usize(usize),
    String(*const TunableString),
}

impl TunableDefault {
    const fn zero_string() -> Self {
        Self::String(core::ptr::from_ref(&EMPTY_TUNABLE_STRING))
    }
}

unsafe impl Sync for TunableDefault {}

#[repr(C)]
#[derive(Clone, Copy)]
struct TunableString {
    ptr: *const u8,
    len: usize,
}

unsafe impl Sync for TunableString {}

static EMPTY_TUNABLE_STRING: TunableString = TunableString {
    ptr: core::ptr::null(),
    len: 0,
};

// Keep this in glibc's generated tunable_id_t order for x86_64. Values are
// the libc defaults, without GLIBC_TUNABLES or legacy environment overrides.
const TUNABLE_DEFAULTS: &[TunableDefault] = &[
    TunableDefault::zero_string(),   // glibc.cpu.hwcaps
    TunableDefault::I32(0),          // glibc.cpu.plt_rewrite
    TunableDefault::I32(0),          // glibc.cpu.prefer_map_32bit_exec
    TunableDefault::Usize(0),        // glibc.cpu.x86_data_cache_size
    TunableDefault::zero_string(),   // glibc.cpu.x86_ibt
    TunableDefault::Usize(0),        // glibc.cpu.x86_memset_non_temporal_threshold
    TunableDefault::Usize(0),        // glibc.cpu.x86_non_temporal_threshold
    TunableDefault::Usize(0),        // glibc.cpu.x86_rep_movsb_threshold
    TunableDefault::Usize(2048),     // glibc.cpu.x86_rep_stosb_threshold
    TunableDefault::Usize(0),        // glibc.cpu.x86_shared_cache_size
    TunableDefault::zero_string(),   // glibc.cpu.x86_shstk
    TunableDefault::I32(0),          // glibc.elf.thp
    TunableDefault::I32(1048576),    // glibc.gmon.maxarcs
    TunableDefault::I32(50),         // glibc.gmon.minarcs
    TunableDefault::Usize(0),        // glibc.malloc.arena_max
    TunableDefault::Usize(0),        // glibc.malloc.arena_test
    TunableDefault::I32(0),          // glibc.malloc.check
    TunableDefault::Usize(0),        // glibc.malloc.hugetlb
    TunableDefault::I32(0),          // glibc.malloc.mmap_max
    TunableDefault::Usize(0),        // glibc.malloc.mmap_threshold
    TunableDefault::Usize(0),        // glibc.malloc.mxfast
    TunableDefault::I32(0),          // glibc.malloc.perturb
    TunableDefault::Usize(0),        // glibc.malloc.tcache_count
    TunableDefault::Usize(0),        // glibc.malloc.tcache_max
    TunableDefault::Usize(131072),   // glibc.malloc.top_pad
    TunableDefault::Usize(0),        // glibc.malloc.trim_threshold
    TunableDefault::I32(0),          // glibc.mem.decorate_maps
    TunableDefault::I32(100),        // glibc.pthread.mutex_spin_count
    TunableDefault::I32(1),          // glibc.pthread.rseq
    TunableDefault::Usize(41943040), // glibc.pthread.stack_cache_size
    TunableDefault::I32(1),          // glibc.pthread.stack_hugetlb
    TunableDefault::I32(2),          // glibc.rtld.dynamic_sort
    TunableDefault::I32(0),          // glibc.rtld.enable_secure
    TunableDefault::I32(1),          // glibc.rtld.execstack
    TunableDefault::Usize(4),        // glibc.rtld.nns
    TunableDefault::Usize(512),      // glibc.rtld.optional_static_tls
];
