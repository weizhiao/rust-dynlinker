use super::{MANAGER, Manager, libc_compat_aliases, normalized_flags};
use crate::{
    ElfLibrary, OpenFlags,
    core_impl::{FileIdentity, LoadedDylib, contains_addr, mapped_end},
};
use alloc::{borrow::ToOwned, string::String, vec::Vec};
use core::ffi::{c_int, c_void};
use spin::{Lazy, RwLock};

impl Drop for ElfLibrary {
    fn drop(&mut self) {
        let mut removed_libs = Vec::new();
        {
            let mut lock = crate::lock_write!(MANAGER);
            let shortname = self.inner.name();
            let Some(flags) = lock.flags(shortname) else {
                return;
            };

            if flags.is_nodelete() {
                return;
            }

            let ref_count = unsafe { self.inner.core_ref().strong_count() };
            let has_global = flags.is_global();
            // Dylib ref in committed link_ctx + dylib ref in this handle's deps list
            // + global ref (if present) + handle's inner ref.
            let threshold = 3 + has_global as usize;

            log::debug!(
                "Drop ElfLibrary [{}], ref count: {}, threshold: {}",
                self.inner.name(),
                ref_count,
                threshold
            );

            if ref_count == threshold {
                log::info!("Destroying dylib [{}]", self.inner.name());
                removed_libs.push(self.inner.clone());

                lock.remove(shortname);

                // Check dependencies
                for dep in self.deps.iter().skip(1) {
                    let dep_shortname = dep.name();
                    let Some(dep_flags) = lock.flags(dep_shortname) else {
                        continue;
                    };
                    if dep_flags.is_nodelete() {
                        continue;
                    }
                    // Dylib ref in committed link_ctx + dylib ref in the owner deps list
                    // + global ref (if present).
                    let dep_threshold = 3 + dep_flags.is_global() as usize;

                    if unsafe { dep.core_ref().strong_count() } == dep_threshold {
                        log::info!("Destroying dylib [{}]", dep.name());
                        removed_libs.push(dep.clone());
                        lock.remove(dep_shortname);
                    }
                }
            }
        }
        for lib in removed_libs {
            let base = lib.base().get();
            let range = base..mapped_end(&lib);
            finalize(base as *mut _, Some(range));
        }
    }
}

pub(crate) fn reserve_pending(
    shortname: String,
    full_name: &str,
    identity: Option<FileIdentity>,
    flags: OpenFlags,
    manager: &mut Manager,
) -> String {
    let flags = normalized_flags(full_name, flags);

    log::debug!(
        "Reserving pending library: [{}] (request: [{}]) flags: [{:?}]",
        shortname,
        full_name,
        flags
    );

    manager.add_pending_reservation(shortname.clone(), flags);

    if let Some(identity) = identity {
        manager.add_identity(identity, &shortname);
    }
    for alias in libc_compat_aliases(&shortname) {
        manager.add_alias(&shortname, alias);
    }

    shortname
}

/// Registers a relocated library in the global manager.
///
/// If the library has `RTLD_GLOBAL` set, it's also added to the global search scope.
pub(crate) fn register_loaded(lib: LoadedDylib, flags: OpenFlags, manager: &mut Manager) {
    let name = lib.name();
    let is_main = name.is_empty();
    let shortname = name.to_owned();
    let flags = normalized_flags(name, flags);

    log::debug!(
        "Registering loaded library: [{}] (full path: [{}]) flags: [{:?}]",
        shortname,
        name,
        flags
    );

    let module_id = manager.add_loaded(shortname.clone(), lib.clone(), flags);

    if let Some(identity) = lib.user_data().file_identity {
        manager.add_identity(identity, &shortname);
    }
    manager.add_alias(&shortname, lib.path().file_name());
    for alias in libc_compat_aliases(&shortname) {
        manager.add_alias(&shortname, alias);
    }
    if flags.is_global() || is_main {
        manager.add_global(module_id);
    }
}

/// Finds a symbol in the global search scope.
///
/// Iterates through all libraries registered with `RTLD_GLOBAL` in the order they were loaded.
pub(crate) unsafe fn global_find<'a, T>(name: &str) -> Option<crate::Symbol<'a, T>> {
    crate::lock_read!(MANAGER)
        .global_values()
        .find_map(|lib| unsafe {
            lib.get::<T>(name).map(|sym| {
                log::trace!(
                    "Lazy Binding: find symbol [{}] from [{}] in global scope ",
                    name,
                    lib.name()
                );
                core::mem::transmute(sym)
            })
        })
}

/// Finds the next occurrence of a symbol after the specified address.
pub(crate) unsafe fn next_find<'a, T>(addr: usize, name: &str) -> Option<crate::Symbol<'a, T>> {
    let lock = crate::lock_read!(MANAGER);
    let libs = lock.all_values().collect::<Vec<_>>();
    // Find the library containing the address
    let idx = libs.iter().position(|v| contains_addr(v, addr))?;

    // Search in all subsequent libraries
    libs.into_iter().skip(idx + 1).find_map(|lib| unsafe {
        lib.get::<T>(name).map(|sym| {
            log::trace!(
                "dlsym: find symbol [{}] from [{}] via RTLD_NEXT",
                name,
                lib.name()
            );
            core::mem::transmute(sym)
        })
    })
}

pub(crate) fn addr2dso(addr: usize) -> Option<ElfLibrary> {
    log::trace!("addr2dso: addr [{:#x}]", addr);
    let manager = crate::lock_read!(MANAGER);
    let entry = manager.all_values().find(|v| contains_addr(v, addr))?;
    let deps = manager.library_scope(entry.name())?;
    Some(ElfLibrary { inner: entry, deps })
}

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

fn finalize(dso_handle: *mut c_void, range: Option<core::ops::Range<usize>>) {
    let mut to_run = Vec::new();
    {
        let mut range = range;
        if range.is_none() && !dso_handle.is_null() {
            let manager = MANAGER.read();
            for v in manager.all_values() {
                if contains_addr(&v, dso_handle as usize) {
                    range = Some(v.base().get()..mapped_end(&v));
                    break;
                }
            }
        }

        let mut all_destructors = DESTRUCTORS.write();
        let mut i = 0;
        while i < all_destructors.len() {
            let matches = match (dso_handle.is_null(), &range) {
                (true, _) => true, // NULL matches all
                (false, Some(r)) => r.contains(&(all_destructors[i].dso_handle as usize)),
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
