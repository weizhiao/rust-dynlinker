#[cfg(feature = "std")]
mod cxa;
mod loader_lock;
mod manager;

#[cfg(feature = "std")]
pub(crate) use cxa::{
    DestructorFn, ThreadAtexitFn, register_module_state, register_thread_destructor,
    unregister_module_state,
};
pub(crate) use loader_lock::{IdentityLookup, RegistryGuard};
pub(crate) use manager::{
    FileIdentity, GlobalLinkContext, GlobalMeta, REGISTRY, destroy_libraries, global_find,
    libc_compat_aliases, library_by_addr, loaded_by_addr, next_find, release_handle,
};
