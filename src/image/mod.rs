mod library;
mod types;

use elf_loader::{arch::NativeArch, image::LoadedCore, memory::HostRegion};

pub use library::{AsFilename, ElfLibrary};
pub use types::ExtraData;

pub(crate) use library::{
    DylibExt, HandleLease, LibrarySnapshot, contains_addr, find_symbol, mapped_end,
};
#[cfg(feature = "std")]
pub(crate) use types::ModuleState;

#[cfg(not(feature = "std"))]
pub type RuntimeLoader = elf_loader::Loader<ExtraData, crate::runtime::rtld::ActiveTlsResolver>;

#[cfg(not(feature = "std"))]
pub(crate) use crate::runtime::rtld::ActiveTlsResolver;
#[cfg(feature = "std")]
pub(crate) use elf_loader::tls::DefaultTlsResolver as ActiveTlsResolver;

#[cfg(not(feature = "std"))]
pub type ElfDylib =
    elf_loader::image::RawDynamic<ExtraData, NativeArch, HostRegion, ActiveTlsResolver>;

pub(crate) type LoadedDylib = LoadedCore<ExtraData, NativeArch, HostRegion, ActiveTlsResolver>;
