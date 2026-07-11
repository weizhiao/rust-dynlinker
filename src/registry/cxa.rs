use super::MANAGER;
use crate::image::{contains_addr, mapped_end};
use alloc::vec::Vec;
use core::ffi::{c_int, c_void};
use spin::{Lazy, RwLock};

fn register_atexit(
    dso_handle: *mut c_void,
    func: unsafe extern "C" fn(*mut c_void),
    arg: *mut c_void,
) -> c_int {
    DESTRUCTORS.write().push(Destructor {
        dso_handle,
        func,
        arg,
    });
    0
}

struct Destructor {
    dso_handle: *mut c_void,
    func: unsafe extern "C" fn(*mut c_void),
    arg: *mut c_void,
}

unsafe impl Send for Destructor {}
unsafe impl Sync for Destructor {}

static DESTRUCTORS: Lazy<RwLock<Vec<Destructor>>> = Lazy::new(|| RwLock::new(Vec::new()));

pub(super) fn finalize(dso_handle: *mut c_void, range: Option<core::ops::Range<usize>>) {
    let mut to_run = Vec::new();
    {
        let mut range = range;
        if range.is_none() && !dso_handle.is_null() {
            let manager = MANAGER.read();
            for lib in manager.all_values() {
                if contains_addr(&lib, dso_handle as usize) {
                    range = Some(lib.base().get()..mapped_end(&lib));
                    break;
                }
            }
        }

        let mut all_destructors = DESTRUCTORS.write();
        let mut i = 0;
        while i < all_destructors.len() {
            let matches = match (dso_handle.is_null(), &range) {
                (true, _) => true,
                (false, Some(range)) => range.contains(&(all_destructors[i].dso_handle as usize)),
                (false, None) => all_destructors[i].dso_handle == dso_handle,
            };
            if matches {
                to_run.push(all_destructors.remove(i));
            } else {
                i += 1;
            }
        }
    }

    if !to_run.is_empty() {
        log::debug!(
            "Running {} destructors for handle {:p}",
            to_run.len(),
            dso_handle
        );
    }
    for destructor in to_run.into_iter().rev() {
        unsafe { (destructor.func)(destructor.arg) };
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __cxa_thread_atexit_impl(
    func: unsafe extern "C" fn(*mut c_void),
    arg: *mut c_void,
    dso_handle: *mut c_void,
) -> c_int {
    register_atexit(dso_handle, func, arg)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __cxa_atexit(
    func: unsafe extern "C" fn(*mut c_void),
    arg: *mut c_void,
    dso_handle: *mut c_void,
) -> c_int {
    register_atexit(dso_handle, func, arg)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __cxa_finalize(dso_handle: *mut c_void) {
    finalize(dso_handle, None);
}
