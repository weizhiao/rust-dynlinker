#[cfg(feature = "std")]
mod cxa;
mod loader_lock;
mod manager;

#[cfg(feature = "std")]
pub(crate) use cxa::{DestructorFn, ThreadAtexitFn, register_thread_destructor};
#[cfg(not(feature = "std"))]
pub(crate) use manager::handle_link_map;
pub(crate) use manager::{
    ModuleLease, REGISTRY, global_find, handle_find, library_by_addr, loaded_by_addr, next_find,
    register_handle, release_handle,
};
