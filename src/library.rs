use crate::{
    OpenFlags, Result,
    abi::link_map::LinkMap,
    error::find_symbol_error,
    registry::{ModuleLease, REGISTRY},
};
use alloc::{boxed::Box, ffi::CString, format, string::String, sync::Arc};
use core::{ffi::c_char, fmt::Debug};
#[cfg(feature = "std")]
use elf_loader::elf::ElfDyn;
use elf_loader::{
    arch::NativeArch,
    elf::ElfPhdr,
    image::{ElfModule, LoadedCore, ModuleHandle, ModuleScope, Symbol},
    memory::{HostRegion, VmAddr},
};

#[cfg(not(feature = "std"))]
pub type RuntimeLoader = elf_loader::Loader<ExtraData, crate::runtime::rtld::ActiveTlsResolver>;

#[cfg(not(feature = "std"))]
pub(crate) use crate::runtime::rtld::ActiveTlsResolver;
#[cfg(feature = "std")]
pub(crate) use elf_loader::tls::DefaultTlsResolver as ActiveTlsResolver;

pub type ElfDylib =
    elf_loader::image::RawDynamic<ExtraData, NativeArch, HostRegion, ActiveTlsResolver>;

pub(crate) type LoadedDylib = LoadedCore<ExtraData, NativeArch, HostRegion, ActiveTlsResolver>;
pub(crate) type NativeElfModule = ElfModule<ExtraData, NativeArch, HostRegion, ActiveTlsResolver>;
pub(crate) type NativeModuleHandle = ModuleHandle<NativeArch, ActiveTlsResolver>;

#[derive(Default)]
pub struct ExtraData {
    pub(crate) c_name: Option<CString>,
    pub(crate) link_map: Option<Box<LinkMap>>,
    #[cfg(feature = "std")]
    pub(crate) dynamic_table: Option<Box<[ElfDyn]>>,
}

impl Debug for ExtraData {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut d = f.debug_struct("UserData");
        d.field("c_name", &self.c_name);
        d.field("link_map", &self.link_map);
        #[cfg(feature = "std")]
        d.field("dynamic_table", &self.dynamic_table);
        d.finish()
    }
}

/// Represents a successfully loaded and relocated dynamic library.
///
/// This is the primary interface for interacting with a loaded library.
#[derive(Clone)]
pub struct ElfLibrary {
    /// The local lookup scope, starting with this library itself.
    pub(crate) scope: ModuleScope<NativeArch, ActiveTlsResolver>,
    // Kept last so loaded library data is released before the lease triggers unloading.
    lease: Arc<ModuleLease>,
}

impl Debug for ElfLibrary {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Dylib")
            .field("name", &self.name())
            .field("base", &self.base())
            .finish()
    }
}

impl ElfLibrary {
    #[inline]
    pub(crate) fn new(
        scope: ModuleScope<NativeArch, ActiveTlsResolver>,
        lease: ModuleLease,
    ) -> Self {
        Self {
            scope,
            lease: Arc::new(lease),
        }
    }

    #[inline]
    pub(crate) fn module(&self) -> &NativeElfModule {
        self.scope
            .first()
            .expect("library scope must contain its root module")
            .downcast_ref()
            .expect("library handle must contain an ELF module")
    }

    /// Get the name of the dynamic library.
    #[inline]
    pub fn name(&self) -> &str {
        self.module().name()
    }

    /// Get the C-style name of the dynamic library.
    #[inline]
    pub fn cname(&self) -> *const c_char {
        self.module()
            .user_data()
            .c_name
            .as_ref()
            .map(|n| n.as_ptr())
            .unwrap_or(core::ptr::null())
    }

    /// Get the current flags from the global registry.
    pub fn flags(&self) -> OpenFlags {
        let registry = REGISTRY.lock();
        registry
            .borrow()
            .flags(self.lease.id())
            .unwrap_or(OpenFlags::empty())
    }

    /// Get the base address of the dynamic library.
    #[inline]
    pub fn base(&self) -> VmAddr {
        self.module().segments().base()
    }

    /// Get the program headers of the dynamic library.
    #[inline]
    pub fn phdrs(&self) -> Option<&[ElfPhdr]> {
        self.module().phdrs()
    }

    /// Get a pointer to a function or static variable by symbol name.
    ///
    /// # Safety
    /// The caller must specify the correct type for the symbol.
    ///
    /// # Examples
    /// ```no_run
    /// # use dlopen_rs::{ElfLibrary, OpenFlags, Symbol};
    /// # let lib = ElfLibrary::dlopen("awesome.so", OpenFlags::RTLD_NOW).unwrap();
    /// unsafe {
    ///     let function: Symbol<unsafe extern fn(f64) -> f64> =
    ///         lib.get("awesome_function").unwrap();
    ///     function(0.42);
    /// }
    /// ```
    ///
    /// ```no_run
    /// # use dlopen_rs::{ElfLibrary, OpenFlags, Symbol};
    /// # let lib = ElfLibrary::dlopen("awesome.so", OpenFlags::RTLD_NOW).unwrap();
    /// unsafe {
    ///     let variable: Symbol<*mut f64> = lib.get("awesome_variable").unwrap();
    ///     **variable = 42.0;
    /// }
    /// ```
    #[inline]
    pub unsafe fn get<'lib, T>(&'lib self, name: &str) -> Result<Symbol<'lib, T>> {
        log::info!("Get the symbol [{}] in [{}]", name, self.scope[0].name());
        self.scope
            .iter()
            .find_map(|lib| unsafe { lib.get::<T>(name) })
            .ok_or(find_symbol_error(format!("can not find symbol:{}", name)))
    }

    /// Load a versioned symbol from the dynamic library.
    ///
    /// ```no_run
    /// # use dlopen_rs::{ElfLibrary, OpenFlags};
    /// # let lib = ElfLibrary::dlopen("awesome.so", OpenFlags::RTLD_NOW).unwrap();
    /// let symbol = unsafe { lib.get_version::<fn()>("function_name", "1.0").unwrap() };
    /// ```
    ///
    /// # Safety
    /// The caller must specify the correct type for the symbol.
    #[cfg(feature = "version")]
    #[inline]
    pub unsafe fn get_version<'lib, T>(
        &'lib self,
        name: &str,
        version: &str,
    ) -> Result<Symbol<'lib, T>> {
        self.scope
            .iter()
            .find_map(|lib| unsafe { lib.get_version(name, version) })
            .ok_or(find_symbol_error(format!("can not find symbol:{}", name)))
    }
}

pub trait AsFilename {
    fn as_filename(&self) -> &str;
}

impl AsFilename for str {
    fn as_filename(&self) -> &str {
        self
    }
}

impl AsFilename for String {
    fn as_filename(&self) -> &str {
        self.as_str()
    }
}

impl<T: AsFilename + ?Sized> AsFilename for &T {
    fn as_filename(&self) -> &str {
        (**self).as_filename()
    }
}

#[cfg(feature = "std")]
impl AsFilename for std::path::Path {
    fn as_filename(&self) -> &str {
        self.to_str().expect("Path must be valid UTF-8")
    }
}

#[cfg(feature = "std")]
impl AsFilename for std::path::PathBuf {
    fn as_filename(&self) -> &str {
        self.to_str().expect("Path must be valid UTF-8")
    }
}

#[cfg(feature = "std")]
impl AsFilename for std::ffi::OsStr {
    fn as_filename(&self) -> &str {
        self.to_str().expect("OsStr must be valid UTF-8")
    }
}

#[cfg(feature = "std")]
impl AsFilename for std::ffi::OsString {
    fn as_filename(&self) -> &str {
        self.to_str().expect("OsString must be valid UTF-8")
    }
}
