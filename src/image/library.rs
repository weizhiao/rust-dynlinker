use super::LoadedDylib;
use crate::{OpenFlags, Result, error::find_symbol_error, registry::MANAGER};
use alloc::{format, string::String, sync::Arc};
use core::{ffi::c_char, fmt::Debug};
use elf_loader::{elf::ElfPhdr, image::Symbol, memory::VmAddr};

/// Represents a successfully loaded and relocated dynamic library.
///
/// This is the primary interface for interacting with a loaded library.
#[derive(Clone)]
pub struct ElfLibrary {
    pub(crate) inner: LoadedDylib,
    /// The flattened dependency scope used by this library.
    pub(crate) deps: Arc<[LoadedDylib]>,
}

impl Debug for ElfLibrary {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Dylib").field("inner", &self.inner).finish()
    }
}

pub(crate) trait DylibExt {
    fn needed_libs(&self) -> &[String];
}

impl DylibExt for LoadedDylib {
    #[inline]
    fn needed_libs(&self) -> &[String] {
        &self.user_data().needed_libs
    }
}

#[inline]
pub(crate) fn find_symbol<'lib, T>(
    libs: &'lib [LoadedDylib],
    name: &str,
) -> Result<Symbol<'lib, T>> {
    log::info!("Get the symbol [{}] in [{}]", name, libs[0].name());
    libs.iter()
        .find_map(|lib| unsafe { lib.get::<T>(name) })
        .ok_or(find_symbol_error(format!("can not find symbol:{}", name)))
}

impl ElfLibrary {
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
        crate::lock_read!(MANAGER)
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
        find_symbol(&self.deps, name)
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
