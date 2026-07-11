use crate::{
    ElfLibrary, Error, Result,
    abi::phdr::{CDlPhdrInfo, DlIteratePhdrCallback},
    registry::MANAGER,
};
use alloc::boxed::Box;
use core::{
    ffi::{c_char, c_int, c_ulonglong, c_void},
    ptr::null_mut,
};
#[cfg(feature = "std")]
use elf_loader::tls::DefaultTlsResolver;
use elf_loader::{elf::ElfPhdr, tls::TlsModuleId};

pub struct DlPhdrInfo<'lib> {
    lib_base: usize,
    lib_name: *const c_char,
    phdrs: &'lib [ElfPhdr],
    dlpi_adds: c_ulonglong,
    dlpi_subs: c_ulonglong,
    tls_modid: usize,
    tls_data: *mut c_void,
}

#[cfg(not(feature = "std"))]
fn tls_data_ptr(mod_id: TlsModuleId) -> *mut c_void {
    crate::runtime::rtld::tls_get_addr_soft(mod_id).cast()
}

#[cfg(feature = "std")]
fn tls_data_ptr(mod_id: TlsModuleId) -> *mut c_void {
    DefaultTlsResolver::get_ptr(mod_id)
        .map(|ptr| ptr.cast())
        .unwrap_or(null_mut())
}

impl DlPhdrInfo<'_> {
    /// Get the name of the dynamic library.
    #[inline]
    pub fn name(&self) -> &str {
        if self.lib_name.is_null() {
            ""
        } else {
            unsafe {
                core::ffi::CStr::from_ptr(self.lib_name)
                    .to_str()
                    .unwrap_or("")
            }
        }
    }

    /// Get the C-style name of the dynamic library.
    #[inline]
    pub fn cname(&self) -> *const c_char {
        self.lib_name
    }

    /// Get the base address of the dynamic library.
    #[inline]
    pub fn base(&self) -> usize {
        self.lib_base
    }

    /// Get the program headers of the dynamic library.
    #[inline]
    pub fn phdrs(&self) -> &[ElfPhdr] {
        self.phdrs
    }
}

impl ElfLibrary {
    /// Iterate over the program headers of all dynamic libraries.
    pub fn dl_iterate_phdr<F>(mut callback: F) -> Result<()>
    where
        F: FnMut(&DlPhdrInfo) -> Result<()>,
    {
        let reader = crate::lock_read!(MANAGER);
        let dlpi_adds = reader.adds();
        let dlpi_subs = reader.subs();
        for lib in reader.all_values() {
            let extra_data = lib.user_data();
            let phdrs = lib.phdrs().unwrap_or(&[]);
            if phdrs.is_empty() {
                continue;
            }
            let tls_modid = lib.tls().mod_id();
            let tls_data = tls_modid.map(tls_data_ptr).unwrap_or(null_mut());
            let info = DlPhdrInfo {
                lib_base: lib.base().get(),
                lib_name: extra_data
                    .c_name
                    .as_ref()
                    .map(|n| n.as_ptr())
                    .unwrap_or(b"\0".as_ptr() as _),
                phdrs,
                dlpi_adds,
                dlpi_subs,
                tls_modid: tls_modid.unwrap_or(TlsModuleId::RESERVED).get(),
                tls_data,
            };
            callback(&info)?;
        }
        Ok(())
    }
}

/// # Safety
/// It is the same as `dl_iterate_phdr`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dl_iterate_phdr(
    callback: Option<DlIteratePhdrCallback>,
    data: *mut c_void,
) -> c_int {
    let Some(callback) = callback else {
        return 0;
    };
    let f = |info: &DlPhdrInfo| {
        let mut c_info = CDlPhdrInfo {
            dlpi_addr: info.lib_base,
            dlpi_name: info.lib_name,
            dlpi_phdr: info.phdrs.as_ptr(),
            dlpi_phnum: info.phdrs.len() as _,
            dlpi_adds: info.dlpi_adds,
            dlpi_subs: info.dlpi_subs,
            dlpi_tls_modid: info.tls_modid,
            dlpi_tls_data: info.tls_data,
        };
        unsafe {
            let ret = callback(&mut c_info, size_of::<CDlPhdrInfo>(), data);
            if ret != 0 {
                return Err(Error::IteratorPhdrError { err: Box::new(ret) });
            }
        };
        Ok(())
    };
    if let Err(err) = ElfLibrary::dl_iterate_phdr(f) {
        if let Error::IteratorPhdrError { err } = err {
            return *err.downcast::<i32>().unwrap();
        }
    }
    0
}
