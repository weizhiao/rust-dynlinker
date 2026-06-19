mod loader;
mod register;
mod traits;
mod types;

pub use loader::DlopenObserver;
pub use loader::ElfLibrary;
pub use traits::AsFilename;
pub use types::ExtraData;

#[cfg(not(feature = "std"))]
pub(crate) use loader::shortname_from_name;
pub(crate) use loader::{
    ActiveTlsResolver, DylibExt, LoadedDylib, contains_addr, find_symbol, mapped_end,
};
#[cfg(not(feature = "std"))]
pub use loader::{ElfDylib, RuntimeLoader};
pub(crate) use register::{
    GlobalMeta, LibraryLookup, MANAGER, Manager, addr2dso, global_find, next_find, register_loaded,
    reserve_pending,
};
pub(crate) use types::{ARGC, ARGV, ENVP, FileIdentity, LinkMap};
