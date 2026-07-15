use alloc::{ffi::CString, vec::Vec};
use core::{
    ffi::{CStr, c_char, c_int, c_void},
    ptr::{copy_nonoverlapping, null_mut},
};

use dlopen_rs::rtld::link_map::LinkMap;
use spin::Mutex;

use super::{serinfo::_dl_rtld_di_serinfo, tls::dl_tls_get_addr_soft};

const RTLD_DI_LMID: c_int = 1;
const RTLD_DI_LINKMAP: c_int = 2;
const RTLD_DI_SERINFO: c_int = 4;
const RTLD_DI_SERINFOSIZE: c_int = 5;
const RTLD_DI_ORIGIN: c_int = 6;
const RTLD_DI_TLS_MODID: c_int = 9;
const RTLD_DI_TLS_DATA: c_int = 10;
const RTLD_DI_PHDR: c_int = 11;
const RTLD_DI_ORIGIN_PATH: c_int = 12;

static ORIGIN_CACHE: Mutex<Vec<OriginCacheEntry>> = Mutex::new(Vec::new());

struct OriginCacheEntry {
    link_map: usize,
    name: usize,
    origin: CString,
}

pub(crate) fn dlfcn_hook() -> *const c_void {
    core::ptr::from_ref(&DLFCN_HOOK).cast()
}

#[repr(C)]
struct DlfcnHook {
    dlopen: extern "C" fn(*const c_char, c_int, *mut c_void) -> *mut c_void,
    dlclose: extern "C" fn(*mut c_void) -> c_int,
    dlsym: extern "C" fn(*mut c_void, *const c_char, *mut c_void) -> *mut c_void,
    dlvsym: extern "C" fn(*mut c_void, *const c_char, *const c_char, *mut c_void) -> *mut c_void,
    dlerror: extern "C" fn() -> *mut c_char,
    dladdr: extern "C" fn(*const c_void, *mut c_void) -> c_int,
    dladdr1: extern "C" fn(*const c_void, *mut c_void, *mut *mut c_void, c_int) -> c_int,
    dlinfo: extern "C" fn(*mut c_void, c_int, *mut c_void) -> c_int,
    dlmopen: extern "C" fn(isize, *const c_char, c_int, *mut c_void) -> *mut c_void,
    libc_dlopen_mode: extern "C" fn(*const c_char, c_int) -> *mut c_void,
    libc_dlsym: extern "C" fn(*mut c_void, *const c_char) -> *mut c_void,
    libc_dlvsym: extern "C" fn(*mut c_void, *const c_char, *const c_char) -> *mut c_void,
    libc_dlclose: extern "C" fn(*mut c_void) -> c_int,
}

unsafe impl Sync for DlfcnHook {}

static DLFCN_HOOK: DlfcnHook = DlfcnHook {
    dlopen: dlfcn_dlopen,
    dlclose: dlfcn_dlclose,
    dlsym: dlfcn_dlsym,
    dlvsym: dlfcn_dlvsym,
    dlerror: dlfcn_dlerror,
    dladdr: dlfcn_dladdr,
    dladdr1: dlfcn_dladdr1,
    dlinfo: dlfcn_dlinfo,
    dlmopen: dlfcn_dlmopen,
    libc_dlopen_mode: libc_dlopen_mode,
    libc_dlsym: libc_dlsym,
    libc_dlvsym: libc_dlvsym,
    libc_dlclose: libc_dlclose,
};

extern "C" fn dlfcn_dlopen(
    filename: *const c_char,
    flags: c_int,
    _caller: *mut c_void,
) -> *mut c_void {
    unsafe { dlopen_rs::api::dlopen(filename, flags).cast_mut() }
}

extern "C" fn dlfcn_dlclose(handle: *mut c_void) -> c_int {
    unsafe { dlopen_rs::api::dlclose(handle.cast_const()) }
}

extern "C" fn dlfcn_dlsym(
    handle: *mut c_void,
    name: *const c_char,
    _caller: *mut c_void,
) -> *mut c_void {
    if name.is_null() {
        return null_mut();
    }

    unsafe { dlopen_rs::api::dlsym(handle.cast_const(), name).cast_mut() }
}

extern "C" fn dlfcn_dlvsym(
    handle: *mut c_void,
    name: *const c_char,
    _version: *const c_char,
    caller: *mut c_void,
) -> *mut c_void {
    dlfcn_dlsym(handle, name, caller)
}

extern "C" fn dlfcn_dlerror() -> *mut c_char {
    null_mut()
}

extern "C" fn dlfcn_dladdr(addr: *const c_void, info: *mut c_void) -> c_int {
    unsafe { dlopen_rs::api::dladdr(addr, info.cast()) }
}

extern "C" fn dlfcn_dladdr1(
    addr: *const c_void,
    info: *mut c_void,
    extra_info: *mut *mut c_void,
    _flags: c_int,
) -> c_int {
    unsafe {
        if !extra_info.is_null() {
            extra_info.write(null_mut());
        }
    }
    dlfcn_dladdr(addr, info)
}

extern "C" fn dlfcn_dlinfo(handle: *mut c_void, request: c_int, arg: *mut c_void) -> c_int {
    if arg.is_null() {
        return -1;
    }

    match request {
        RTLD_DI_SERINFO => {
            _dl_rtld_di_serinfo(handle, arg.cast(), false);
            0
        }
        RTLD_DI_SERINFOSIZE => {
            _dl_rtld_di_serinfo(handle, arg.cast(), true);
            0
        }
        _ => {
            let link_map = unsafe { dlopen_rs::rtld::handle_link_map(handle) };
            if link_map.is_null() {
                return -1;
            }

            unsafe { dlinfo_link_map(link_map, request, arg) }
        }
    }
}

unsafe fn dlinfo_link_map(link_map: *mut LinkMap, request: c_int, arg: *mut c_void) -> c_int {
    match request {
        RTLD_DI_LMID => {
            unsafe { arg.cast::<isize>().write((*link_map).l_ns) };
            0
        }
        RTLD_DI_LINKMAP => {
            unsafe { arg.cast::<*mut LinkMap>().write(link_map) };
            0
        }
        RTLD_DI_ORIGIN => unsafe { write_origin(link_map, arg.cast()) },
        RTLD_DI_ORIGIN_PATH => unsafe { write_origin_path(link_map, arg.cast()) },
        RTLD_DI_TLS_MODID => {
            unsafe { arg.cast::<usize>().write((*link_map).l_tls_modid) };
            0
        }
        RTLD_DI_TLS_DATA => {
            let data = if unsafe { (*link_map).l_tls_modid } == 0 {
                null_mut()
            } else {
                dl_tls_get_addr_soft(link_map)
            };
            unsafe { arg.cast::<*mut c_void>().write(data) };
            0
        }
        RTLD_DI_PHDR => unsafe {
            arg.cast::<*const c_void>().write((*link_map).l_phdr.cast());
            (*link_map).l_phnum as c_int
        },
        _ => -1,
    }
}

unsafe fn write_origin(link_map: *mut LinkMap, dst: *mut c_char) -> c_int {
    if dst.is_null() {
        return -1;
    }

    let name = unsafe { (*link_map).l_name };
    if name.is_null() {
        unsafe { dst.write(0) };
        return 0;
    }

    let name = unsafe { CStr::from_ptr(name) }.to_bytes();
    let origin = origin_from_name(name);
    unsafe {
        copy_nonoverlapping(origin.as_ptr().cast(), dst, origin.len());
        dst.add(origin.len()).write(0);
    }
    0
}

unsafe fn write_origin_path(link_map: *mut LinkMap, dst: *mut *const c_char) -> c_int {
    if dst.is_null() {
        return -1;
    }

    let name = unsafe { (*link_map).l_name };
    let origin = origin_path_ptr(link_map, name);
    unsafe { dst.write(origin) };
    0
}

fn origin_path_ptr(link_map: *mut LinkMap, name: *const c_char) -> *const c_char {
    if name.is_null() {
        return core::ptr::null();
    }

    let link_map_key = link_map.addr();
    let name_key = name.addr();
    let mut cache = ORIGIN_CACHE.lock();
    if let Some(entry) = cache
        .iter()
        .find(|entry| entry.link_map == link_map_key && entry.name == name_key)
    {
        return entry.origin.as_ptr();
    }

    let name = unsafe { CStr::from_ptr(name) }.to_bytes();
    let origin = origin_from_name(name);
    let origin = CString::new(origin).expect("origin must not contain interior NUL bytes");
    let ptr = origin.as_ptr();
    cache.push(OriginCacheEntry {
        link_map: link_map_key,
        name: name_key,
        origin,
    });
    ptr
}

fn origin_from_name(name: &[u8]) -> &[u8] {
    match name.iter().rposition(|&byte| byte == b'/') {
        Some(0) => &name[..1],
        Some(index) => &name[..index],
        None if name.is_empty() => b"",
        None => b".",
    }
}

extern "C" fn dlfcn_dlmopen(
    _nsid: isize,
    filename: *const c_char,
    flags: c_int,
    caller: *mut c_void,
) -> *mut c_void {
    dlfcn_dlopen(filename, flags, caller)
}

extern "C" fn libc_dlopen_mode(filename: *const c_char, flags: c_int) -> *mut c_void {
    dlfcn_dlopen(filename, flags, null_mut())
}

extern "C" fn libc_dlsym(handle: *mut c_void, name: *const c_char) -> *mut c_void {
    dlfcn_dlsym(handle, name, null_mut())
}

extern "C" fn libc_dlvsym(
    handle: *mut c_void,
    name: *const c_char,
    version: *const c_char,
) -> *mut c_void {
    dlfcn_dlvsym(handle, name, version, null_mut())
}

extern "C" fn libc_dlclose(handle: *mut c_void) -> c_int {
    dlfcn_dlclose(handle)
}
