use super::REGISTRY;
use crate::library::ModuleState;
use alloc::{boxed::Box, sync::Arc, sync::Weak, vec::Vec};
use core::{
    ffi::{c_int, c_void},
    ops::Range,
};
use spin::{Lazy, RwLock};

pub(crate) type DestructorFn = unsafe extern "C" fn(*mut c_void);
pub(crate) type ThreadAtexitFn =
    unsafe extern "C" fn(DestructorFn, *mut c_void, *mut c_void) -> c_int;

struct ThreadDestructor {
    func: DestructorFn,
    arg: *mut c_void,
    state: Option<Arc<ModuleState>>,
}

struct ModuleStateEntry {
    range: Range<usize>,
    state: Weak<ModuleState>,
}

static MODULE_STATES: Lazy<RwLock<Vec<ModuleStateEntry>>> = Lazy::new(|| RwLock::new(Vec::new()));

pub(crate) fn register_module_state(range: Range<usize>, state: &Arc<ModuleState>) {
    MODULE_STATES.write().push(ModuleStateEntry {
        range,
        state: Arc::downgrade(state),
    });
}

pub(crate) fn unregister_module_state(state: &Arc<ModuleState>) {
    MODULE_STATES
        .write()
        .retain(|entry| !core::ptr::eq(entry.state.as_ptr(), Arc::as_ptr(state)));
}

fn module_state_by_addr(addr: usize) -> Option<Arc<ModuleState>> {
    MODULE_STATES
        .read()
        .iter()
        .find(|entry| entry.range.contains(&addr))
        .and_then(|entry| entry.state.upgrade())
}

unsafe extern "C" fn run_thread_destructor(arg: *mut c_void) {
    let destructor = unsafe { Box::from_raw(arg.cast::<ThreadDestructor>()) };
    unsafe { (destructor.func)(destructor.arg) };

    let state = destructor.state.clone();
    if let Some(state) = state.as_ref() {
        state.unregister_tls_dtor();
    }
    drop(destructor);

    if state.is_some() {
        let registry = REGISTRY.lock();
        let libraries = registry.collect_unreachable();
        super::destroy_libraries(libraries);
    }
}

pub(crate) unsafe fn register_thread_destructor(
    thread_atexit: ThreadAtexitFn,
    func: DestructorFn,
    arg: *mut c_void,
    dso_handle: *mut c_void,
) -> c_int {
    let state = module_state_by_addr(dso_handle as usize);
    if state
        .as_ref()
        .is_some_and(|state| !state.register_tls_dtor())
    {
        return -1;
    }

    let custom_owner = state.is_some();
    let destructor = Box::new(ThreadDestructor { func, arg, state });
    let raw = Box::into_raw(destructor);
    let glibc_owner = if custom_owner {
        run_thread_destructor as *const () as *mut c_void
    } else {
        dso_handle
    };
    let result = unsafe { thread_atexit(run_thread_destructor, raw.cast(), glibc_owner) };
    if result != 0 {
        let destructor = unsafe { Box::from_raw(raw) };
        if let Some(state) = destructor.state.as_ref() {
            state.unregister_tls_dtor();
        }
        drop(destructor);
    }
    result
}
