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
pub(crate) use crate::runtime::rtld::ActiveTlsResolver;
#[cfg(feature = "std")]
pub(crate) use elf_loader::tls::DefaultTlsResolver as ActiveTlsResolver;

pub type ElfDylib =
    elf_loader::image::RawDynamic<Option<ExtraData>, NativeArch, HostRegion, ActiveTlsResolver>;

pub(crate) type LoadedDylib =
    LoadedCore<Option<ExtraData>, NativeArch, HostRegion, ActiveTlsResolver>;
pub(crate) type NativeElfModule =
    ElfModule<Option<ExtraData>, NativeArch, HostRegion, ActiveTlsResolver>;
pub(crate) type NativeModuleHandle = ModuleHandle<NativeArch, ActiveTlsResolver>;
pub(crate) type NativeModuleScope = ModuleScope<NativeArch, ActiveTlsResolver>;

pub struct ExtraData {
    c_name: CString,
    link_map: Box<LinkMap>,
    #[cfg(feature = "std")]
    dynamic_table: Box<[ElfDyn]>,
}

impl ExtraData {
    #[inline]
    pub(crate) fn new(c_name: CString, link_map: Box<LinkMap>) -> Self {
        Self {
            c_name,
            link_map,
            #[cfg(feature = "std")]
            dynamic_table: Box::default(),
        }
    }

    #[cfg(feature = "std")]
    #[inline]
    pub(crate) fn with_dynamic_table(
        c_name: CString,
        link_map: Box<LinkMap>,
        dynamic_table: Box<[ElfDyn]>,
    ) -> Self {
        Self {
            c_name,
            link_map,
            dynamic_table,
        }
    }

    #[inline]
    pub(crate) const fn c_name(&self) -> &CString {
        &self.c_name
    }

    #[inline]
    pub(crate) fn link_map(&self) -> *mut LinkMap {
        core::ptr::from_ref(self.link_map.as_ref()).cast_mut()
    }
}

impl Debug for ExtraData {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut d = f.debug_struct("ExtraData");
        d.field("c_name", &self.c_name);
        d.field("link_map", &self.link_map);
        #[cfg(feature = "std")]
        d.field("dynamic_table", &self.dynamic_table);
        d.finish()
    }
}

pub(crate) struct OpenedLibrary {
    /// The stable dependency group used for local symbol lookup.
    scope: NativeModuleScope,
    // Kept last so loaded library data is released before the lease triggers unloading.
    lease: ModuleLease,
}

impl OpenedLibrary {
    #[inline]
    pub(crate) const fn new(scope: NativeModuleScope, lease: ModuleLease) -> Self {
        Self { scope, lease }
    }

    #[inline]
    pub(crate) const fn scope(&self) -> &NativeModuleScope {
        &self.scope
    }

    #[inline]
    pub(crate) fn module(&self) -> &NativeElfModule {
        self.scope()
            .first()
            .expect("library scope must contain its root module")
            .downcast_ref()
            .expect("library handle must contain an ELF module")
    }

    #[inline]
    pub(crate) fn link_map(&self) -> *mut LinkMap {
        self.module()
            .user_data()
            .as_ref()
            .expect("library module must have extra data")
            .link_map()
    }

    #[inline]
    pub(crate) fn into_lease(self) -> ModuleLease {
        self.lease
    }
}

/// Represents a successfully loaded and relocated dynamic library.
///
/// This is the primary interface for interacting with a loaded library.
#[derive(Clone)]
pub struct ElfLibrary {
    opened: Arc<OpenedLibrary>,
}

impl From<OpenedLibrary> for ElfLibrary {
    #[inline]
    fn from(opened: OpenedLibrary) -> Self {
        Self {
            opened: Arc::new(opened),
        }
    }
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
    pub(crate) fn scope(&self) -> &NativeModuleScope {
        self.opened.scope()
    }

    #[inline]
    pub(crate) fn module(&self) -> &NativeElfModule {
        self.opened.module()
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
            .as_ref()
            .expect("library module must have extra data")
            .c_name()
            .as_ptr()
    }

    /// Get the current flags from the global registry.
    pub fn flags(&self) -> OpenFlags {
        let registry = REGISTRY.lock();
        registry
            .borrow()
            .flags(self.opened.lease.id())
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
        log::info!("Get the symbol [{}] in [{}]", name, self.scope()[0].name());
        self.scope()
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
        self.scope()
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
