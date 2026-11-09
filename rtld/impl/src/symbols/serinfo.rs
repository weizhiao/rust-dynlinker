use core::{
    ffi::{c_char, c_uint, c_void},
    ptr::copy_nonoverlapping,
};

#[unsafe(no_mangle)]
pub extern "C" fn _dl_rtld_di_serinfo(
    _loader: *mut c_void,
    serinfo: *mut DlSerinfo,
    counting: bool,
) {
    if serinfo.is_null() {
        return;
    }

    let paths = dlopen_rs::rtld::default_library_paths();
    let path_count = paths.len();
    let strings_size = paths
        .iter()
        .map(|path| path.to_bytes_with_nul().len())
        .sum::<usize>();
    let total_size = core::mem::size_of::<DlSerinfo>()
        + path_count * core::mem::size_of::<DlSerpath>()
        + strings_size;

    unsafe {
        (*serinfo).dls_size = total_size;
        (*serinfo).dls_cnt = path_count as c_uint;
        if counting {
            return;
        }

        let serpath = serinfo
            .cast::<u8>()
            .add(core::mem::size_of::<DlSerinfo>())
            .cast::<DlSerpath>();
        let mut name = serpath.add(path_count).cast::<c_char>();
        for (index, path) in paths.iter().enumerate() {
            let path = path.to_bytes_with_nul();
            copy_nonoverlapping(path.as_ptr(), name.cast(), path.len());
            serpath.add(index).write(DlSerpath {
                dls_name: name,
                dls_flags: 0,
            });
            name = name.add(path.len());
        }
    }
}

#[repr(C)]
pub struct DlSerinfo {
    dls_size: usize,
    dls_cnt: c_uint,
}

#[repr(C)]
pub struct DlSerpath {
    dls_name: *mut c_char,
    dls_flags: c_uint,
}
