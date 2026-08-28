#[cfg(feature = "std")]
mod cxa;
mod loader_lock;
mod manager;

#[cfg(feature = "std")]
pub(crate) use cxa::{DestructorFn, ThreadAtexitFn, register_thread_destructor};
pub(crate) use manager::{
    ModuleLease, REGISTRY, global_find, library_by_addr, loaded_by_addr, next_find,
};
