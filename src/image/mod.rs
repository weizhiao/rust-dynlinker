mod address;
mod library;
mod observer;
mod types;

use elf_loader::{arch::NativeArch, image::LoadedCore, memory::HostRegion};

pub use address::DlInfo;
pub use library::{AsFilename, ElfLibrary};
pub use observer::DlopenObserver;
pub use types::ExtraData;

pub(crate) use address::{contains_addr, dladdr_raw, mapped_end};
pub(crate) use library::{DylibExt, find_symbol};

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
