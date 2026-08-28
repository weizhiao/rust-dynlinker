use super::REGISTRY;
use crate::registry::ModuleLease;
use alloc::boxed::Box;
use core::ffi::{c_int, c_void};

pub(crate) type DestructorFn = unsafe extern "C" fn(*mut c_void);
pub(crate) type ThreadAtexitFn =
    unsafe extern "C" fn(DestructorFn, *mut c_void, *mut c_void) -> c_int;

struct ThreadDestructor {
    func: DestructorFn,
    arg: *mut c_void,
    _lease: Option<ModuleLease>,
}

unsafe extern "C" fn run_thread_destructor(arg: *mut c_void) {
    let destructor = unsafe { Box::from_raw(arg.cast::<ThreadDestructor>()) };
    unsafe { (destructor.func)(destructor.arg) };
    drop(destructor);
}

pub(crate) unsafe fn register_thread_destructor(
    thread_atexit: ThreadAtexitFn,
    func: DestructorFn,
    arg: *mut c_void,
    dso_handle: *mut c_void,
) -> c_int {
    let lease = {
        let registry = REGISTRY.lock();
        registry
            .borrow_mut()
            .acquire_module_by_addr(dso_handle as usize)
    };

    let custom_owner = lease.is_some();
    let destructor = Box::new(ThreadDestructor {
        func,
        arg,
        _lease: lease,
    });
    let raw = Box::into_raw(destructor);
    let glibc_owner = if custom_owner {
        run_thread_destructor as *const () as *mut c_void
    } else {
        dso_handle
    };
    let result = unsafe { thread_atexit(run_thread_destructor, raw.cast(), glibc_owner) };
    if result != 0 {
        drop(unsafe { Box::from_raw(raw) });
    }
    result
}
