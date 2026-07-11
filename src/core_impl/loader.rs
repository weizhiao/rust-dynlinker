use super::types::{ARGC, ARGV, ENVP, ExtraData};
use crate::abi::link_map::LinkMap;
use crate::utils::debug::add_debug_link_map;
use crate::{OpenFlags, Result, error::find_symbol_error};
use alloc::{
    borrow::ToOwned,
    boxed::Box,
    ffi::CString,
    format,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use core::{
    ffi::{c_char, c_int},
    fmt::Debug,
    ptr::null,
};
use elf_loader::{
    arch::NativeArch,
    elf::{ElfDyn, ElfPhdr, ElfProgramType},
    image::{LoadedCore, Symbol},
    memory::{HostRegion, RegionAccess, VmAddr},
    observer::{AfterDynamicLoadEvent, InitEvent, LoadObserver, RelocationObserver},
    tls::TlsResolver,
};

#[cfg(not(feature = "std"))]
use elf_loader::image::RawDynamic;

#[cfg(not(feature = "std"))]
pub type RuntimeLoader = elf_loader::Loader<ExtraData, crate::rtld::ActiveTlsResolver>;

#[cfg(not(feature = "std"))]
pub(crate) use crate::rtld::ActiveTlsResolver;
#[cfg(feature = "std")]
pub(crate) use elf_loader::tls::DefaultTlsResolver as ActiveTlsResolver;
#[cfg(not(feature = "std"))]
pub type ElfDylib = RawDynamic<ExtraData, NativeArch, HostRegion, ActiveTlsResolver>;
pub(crate) type LoadedDylib = LoadedCore<ExtraData, NativeArch, HostRegion, ActiveTlsResolver>;

#[derive(Clone, Copy)]
pub struct DlopenObserver;

impl LoadObserver<ExtraData> for DlopenObserver {
    fn on_after_dynamic_load<R: RegionAccess, Tls: TlsResolver<NativeArch>>(
        &mut self,
        mut event: AfterDynamicLoadEvent<'_, ExtraData, NativeArch, R, Tls>,
    ) -> elf_loader::Result<()> {
        let dylib = event.raw_mut();
        let needed_libs = dylib
            .needed_libs()
            .iter()
            .map(|s: &&str| s.to_string())
            .collect::<Vec<_>>();

        let name = dylib.name().to_string();
        let path = dylib.path().as_str().to_owned();
        let link_name = if path.is_empty() {
            name.as_str()
        } else {
            path.as_str()
        };
        let base = dylib.base();
        let dynamic_ptr = dylib
            .phdrs()
            .iter()
            .find(|p: &&ElfPhdr| p.program_type() == ElfProgramType::DYNAMIC)
            .map(|p: &ElfPhdr| (base + p.p_vaddr()).as_mut_ptr::<ElfDyn>())
            .unwrap_or(core::ptr::null_mut());

        let phdrs = dylib.phdrs();
        let phdr = if phdrs.is_empty() {
            null()
        } else {
            phdrs.as_ptr().cast()
        };
        let phnum = phdrs.len().min(u16::MAX as usize) as u16;
        let entry = dylib.entry();
        let tls = dylib.tls();
        let tls_mod_id = tls.mod_id().map(|id| id.get());
        let tls_tp_offset = tls.tp_offset().map(|offset| offset.get());

        let dynamic_table = (!dynamic_ptr.is_null())
            .then(|| unsafe { copy_dynamic_table(dynamic_ptr) }.into_boxed_slice());
        let c_name = CString::new(link_name).unwrap();

        let mut link_map = Box::new(LinkMap {
            l_addr: base.as_mut_ptr(),
            l_name: c_name.as_ptr(),
            l_ld: dynamic_ptr as *mut _,
            l_next: core::ptr::null_mut(),
            l_prev: core::ptr::null_mut(),
            l_phdr: phdr,
            l_entry: entry,
            l_phnum: phnum,
            ..LinkMap::zero()
        });
        populate_link_map_tls(&mut link_map, base, phdrs, tls_mod_id, tls_tp_offset);
        link_map.l_real = link_map.as_mut() as *mut LinkMap;

        unsafe { add_debug_link_map(link_map.as_mut()) };
        let user_data = dylib.user_data_mut().unwrap();
        user_data.needed_libs = needed_libs;
        user_data.dynamic_table = dynamic_table;
        user_data.link_map = Some(link_map);
        user_data.c_name = Some(c_name);
        Ok(())
    }
}

impl RelocationObserver for DlopenObserver {
    fn on_init<D: 'static, R: RegionAccess, Tls: TlsResolver<NativeArch>>(
        &mut self,
        event: &mut InitEvent<'_, D, NativeArch, R, Tls>,
    ) -> elf_loader::Result<()> {
        let argc = unsafe { *core::ptr::addr_of!(ARGC) };
        let argv = unsafe { *core::ptr::addr_of!(ARGV) };
        let envp = unsafe { *core::ptr::addr_of!(ENVP) as *const *mut c_char };
        type InitFn = unsafe extern "C" fn(c_int, *const *mut c_char, *const *mut c_char);
        for init in event.lifecycle().func_addrs() {
            let init: InitFn = unsafe { core::mem::transmute(init) };
            unsafe { init(argc as c_int, argv, envp) };
        }
        event.lifecycle_mut().clear();
        Ok(())
    }
}

/// Searches for a symbol in a list of relocated libraries.
///
/// Iterates through the provided libraries in order and returns the first matching symbol.
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

fn populate_link_map_tls(
    link_map: &mut LinkMap,
    base: VmAddr,
    phdrs: &[ElfPhdr],
    tls_mod_id: Option<usize>,
    tls_tp_offset: Option<isize>,
) {
    let Some(mod_id) = tls_mod_id else {
        return;
    };
    link_map.l_tls_modid = mod_id;
    link_map.l_tls_offset = tls_tp_offset.unwrap_or(0);

    let Some(tls) = phdrs
        .iter()
        .find(|phdr| phdr.program_type() == ElfProgramType::TLS)
    else {
        return;
    };
    link_map.l_tls_blocksize = tls.p_memsz();
    link_map.l_tls_align = tls.p_align();
    link_map.l_tls_firstbyte_offset = tls.p_vaddr().get() & tls.p_align().saturating_sub(1);
    link_map.l_tls_initimage_size = tls.p_filesz();
    if tls.p_filesz() != 0 {
        link_map.l_tls_initimage = (base + tls.p_vaddr()).as_mut_ptr();
    }
}

unsafe fn copy_dynamic_table(mut dynamic: *const ElfDyn) -> Vec<ElfDyn> {
    let mut table = Vec::new();
    while !dynamic.is_null() {
        let entry = unsafe { &*dynamic };
        table.push(ElfDyn::new(entry.tag(), entry.value()));
        if entry.tag() == elf_loader::elf::ElfDynamicTag::NULL {
            break;
        }
        dynamic = unsafe { dynamic.add(1) };
    }
    table
}

/// Represents a successfully loaded and relocated dynamic library.
///
/// This is the primary interface for interacting with a loaded library,
/// providing methods to look up symbols and inspect metadata.
#[derive(Clone)]
pub struct ElfLibrary {
    pub(crate) inner: LoadedDylib,
    /// The flattened dependency scope (Searchlist) used by this library.
    pub(crate) deps: Arc<[LoadedDylib]>,
}

impl Debug for ElfLibrary {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Dylib").field("inner", &self.inner).finish()
    }
}

pub trait DylibExt {
    fn needed_libs(&self) -> &[String];
}

impl DylibExt for LoadedDylib {
    #[inline]
    fn needed_libs(&self) -> &[String] {
        &self.user_data().needed_libs
    }
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

    /// Get the current flags of the dynamic library from the global registry.
    pub fn flags(&self) -> OpenFlags {
        use super::register::MANAGER;
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

    /// Get the needed libs' name of the elf object.
    #[inline]
    pub fn needed_libs(&self) -> &[String] {
        self.inner.needed_libs()
    }

    /// Get a pointer to a function or static variable by symbol name.
    ///
    /// The symbol is interpreted as-is; no mangling is done. This means that symbols like `x::y` are
    /// most likely invalid.
    ///
    /// # Safety
    /// Users of this API must specify the correct type of the function or variable loaded.
    ///
    /// # Examples
    /// ```no_run
    /// # use dlopen_rs::{Symbol, ElfLibrary ,OpenFlags};
    /// # let lib = ElfLibrary::dlopen("awesome.so", OpenFlags::RTLD_NOW).unwrap();
    /// unsafe {
    ///     let awesome_function: Symbol<unsafe extern fn(f64) -> f64> =
    ///         lib.get("awesome_function").unwrap();
    ///     awesome_function(0.42);
    /// }
    /// ```
    /// A static variable may also be loaded and inspected:
    /// ```no_run
    /// # use dlopen_rs::{Symbol, ElfLibrary ,OpenFlags};
    /// # let lib = ElfLibrary::dlopen("awesome.so", OpenFlags::RTLD_NOW).unwrap();
    /// unsafe {
    ///     let awesome_variable: Symbol<*mut f64> = lib.get("awesome_variable").unwrap();
    ///     **awesome_variable = 42.0;
    /// };
    /// ```
    #[inline]
    pub unsafe fn get<'lib, T>(&'lib self, name: &str) -> Result<Symbol<'lib, T>> {
        find_symbol(&self.deps, name)
    }

    /// Load a versioned symbol from the dynamic library.
    ///
    /// # Examples
    /// ```no_run
    /// # use dlopen_rs::{Symbol, ElfLibrary ,OpenFlags};
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

#[inline]
pub(crate) fn contains_addr(lib: &LoadedDylib, addr: usize) -> bool {
    lib.segments()
        .contains_addr(elf_loader::memory::VmAddr::new(addr))
}

#[inline]
pub(crate) fn mapped_end(lib: &LoadedDylib) -> usize {
    let base = lib.base().get();
    lib.segments()
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
