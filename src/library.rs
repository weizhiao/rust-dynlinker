use crate::{
    OpenFlags, Result,
    abi::link_map::LinkMap,
    error::find_symbol_error,
    registry::{ModuleLease, REGISTRY},
};
use alloc::{boxed::Box, ffi::CString, format, string::String, sync::Arc, vec::Vec};
use core::{
    ffi::c_char,
    fmt::Debug,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};
use elf_loader::{
    arch::NativeArch,
    elf::{ElfDyn, ElfPhdr},
    image::{LoadedCore, Symbol},
    memory::{HostRegion, VmAddr},
};
use spin::Once;

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

const UNLOADING: usize = 1 << (usize::BITS - 1);

#[derive(Default)]
pub(crate) struct ModuleState {
    tls_dtors: AtomicUsize,
}

impl ModuleState {
    #[cfg(feature = "std")]
    pub(crate) fn register_tls_dtor(&self) -> bool {
        self.tls_dtors
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |state| {
                if state & UNLOADING != 0 || state == UNLOADING - 1 {
                    None
                } else {
                    Some(state + 1)
                }
            })
            .is_ok()
    }

    #[cfg(feature = "std")]
    pub(crate) fn unregister_tls_dtor(&self) {
        let previous = self.tls_dtors.fetch_sub(1, Ordering::Release);
        debug_assert!(
            previous > 0 && previous & UNLOADING == 0,
            "TLS destructor count must have a matching registration"
        );
    }

    #[inline]
    pub(crate) fn has_tls_dtors(&self) -> bool {
        self.tls_dtors.load(Ordering::Acquire) != 0
    }

    pub(crate) fn begin_unload(&self) -> bool {
        self.tls_dtors
            .compare_exchange(0, UNLOADING, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    pub(crate) fn cancel_unload(&self) {
        let result =
            self.tls_dtors
                .compare_exchange(UNLOADING, 0, Ordering::Release, Ordering::Relaxed);
        debug_assert!(result.is_ok(), "only a planned unload can be cancelled");
    }
}

#[derive(Default)]
pub struct ExtraData {
    pub(crate) c_name: Option<CString>,
    pub(crate) link_map: Option<Box<LinkMap>>,
    pub(crate) needed_libs: Vec<String>,
    pub(crate) dynamic_table: Option<Box<[ElfDyn]>>,
    pub(crate) fini: Once<Box<[VmAddr]>>,
    pub(crate) fini_ran: Arc<AtomicBool>,
    pub(crate) state: Arc<ModuleState>,
}

impl Debug for ExtraData {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut d = f.debug_struct("UserData");
        d.field("c_name", &self.c_name);
        d.field("link_map", &self.link_map);
        d.field("needed_libs", &self.needed_libs);
        d.field("dynamic_table", &self.dynamic_table);
        d.field("fini", &self.fini.get());
        d.finish()
    }
}

/// Represents a successfully loaded and relocated dynamic library.
///
/// This is the primary interface for interacting with a loaded library.
#[derive(Clone)]
pub struct ElfLibrary {
    pub(crate) inner: LoadedDylib,
    /// The flattened dependency scope used by this library.
    pub(crate) deps: Arc<[LoadedDylib]>,
    // Kept last so loaded library data is released before the lease triggers unloading.
    _lease: Arc<ModuleLease>,
}

impl Debug for ElfLibrary {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Dylib").field("inner", &self.inner).finish()
    }
}

pub(crate) trait DylibExt {
    fn needed_libs(&self) -> &[String];
    fn contains_addr(&self, addr: usize) -> bool;
    fn mapped_end(&self) -> usize;
}

impl DylibExt for LoadedDylib {
    #[inline]
    fn needed_libs(&self) -> &[String] {
        &self.user_data().needed_libs
    }

    #[inline]
    fn contains_addr(&self, addr: usize) -> bool {
        self.segments().contains_addr(VmAddr::new(addr))
    }

    #[inline]
    fn mapped_end(&self) -> usize {
        let base = self.base().get();
        self.segments()
            .ranges()
            .iter()
            .filter_map(|range| {
                range
                    .offset
                    .get()
                    .checked_add(range.len)
                    .and_then(|end| base.checked_add(end))
            })
            .max()
            .unwrap_or(base)
    }
}

impl ElfLibrary {
    #[inline]
    pub(crate) fn new(inner: LoadedDylib, deps: Arc<[LoadedDylib]>, lease: ModuleLease) -> Self {
        Self {
            inner,
            deps,
            _lease: Arc::new(lease),
        }
    }

    /// Get the name of the dynamic library.
    #[inline]
    pub fn name(&self) -> &str {
        self.inner.name()
    }

    /// Get the C-style name of the dynamic library.
    #[inline]
    pub fn cname(&self) -> *const c_char {
        self.inner
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
            .flags(self.name())
            .unwrap_or(OpenFlags::empty())
    }

    /// Get the base address of the dynamic library.
    #[inline]
    pub fn base(&self) -> VmAddr {
        self.inner.base()
    }

    /// Get the program headers of the dynamic library.
    #[inline]
    pub fn phdrs(&self) -> Option<&[ElfPhdr]> {
        self.inner.phdrs()
    }

    /// Get the names of this object's needed libraries.
    #[inline]
    pub fn needed_libs(&self) -> &[String] {
        self.inner.needed_libs()
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
        log::info!("Get the symbol [{}] in [{}]", name, self.deps[0].name());
        self.deps
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
    #[cfg(feature = "version")]
    #[inline]
    pub unsafe fn get_version<'lib, T>(
        &'lib self,
        name: &str,
        version: &str,
    ) -> Result<Symbol<'lib, T>> {
        unsafe {
            self.inner
                .get_version(name, version)
                .ok_or(find_symbol_error(format!("can not find symbol:{}", name)))
        }
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
