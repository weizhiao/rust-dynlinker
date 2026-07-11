use super::{FileIdentity, MANAGER, Manager, cxa::finalize, libc_compat_aliases, normalized_flags};
use crate::{
    ElfLibrary, OpenFlags,
    image::{LoadedDylib, contains_addr, mapped_end},
};
use alloc::{borrow::ToOwned, string::String, vec::Vec};

impl Drop for ElfLibrary {
    fn drop(&mut self) {
        let mut removed_libs = Vec::new();
        {
            let mut lock = crate::lock_write!(MANAGER);
            let shortname = self.inner.name();
            let Some(flags) = lock.flags(shortname) else {
                return;
            };

            if flags.is_nodelete() || flags.is_global() {
                return;
            }

            let ref_count = unsafe { self.inner.core_ref().strong_count() };
            // Dylib ref in committed link_ctx + dylib ref in this handle's deps list
            // + handle's inner ref.
            let threshold = 3;

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
                    if dep_flags.is_global() {
                        continue;
                    }

                    // Dylib ref in committed link_ctx + dylib ref in the owner deps list
                    // + current handle's dependency list.
                    let dep_threshold = 3;

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

    manager.add_pending_reservation(shortname.clone(), identity, flags);
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
    lock.all_values()
        .skip_while(|lib| !contains_addr(lib, addr))
        .skip(1)
        .find_map(|lib| unsafe {
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
