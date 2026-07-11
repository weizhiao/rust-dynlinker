pub use crate::abi::{auxv, debug, elf, link_map, memory, relocation};

use crate::{
    OpenFlags, Result,
    api::dlopen::{LinkRoot, OpenContext, link_root},
    core_impl::{ARGC, ARGV, ENVP, ElfLibrary, LoadedDylib, MANAGER, register_loaded},
};
use alloc::{borrow::ToOwned, boxed::Box, vec::Vec};
use core::ffi::{c_char, c_int, c_void};

#[doc(hidden)]
pub use self::tls::{ActiveTlsResolver, RtldTlsOps};
#[doc(hidden)]
pub use crate::core_impl::{DlopenObserver, ElfDylib, ExtraData, RuntimeLoader};
#[doc(hidden)]
pub use elf_loader::{
    Loader as ElfLoader, Result as ElfResult,
    arch::NativeArch,
    error::TlsError,
    image::RawExec,
    input::PathBuf,
    memory::VmAddr,
    tls::{
        DefaultTlsResolver, TlsImageSource, TlsIndex, TlsInfo, TlsModuleId, TlsResolver,
        TlsTemplate, TlsTpOffset,
    },
};

#[doc(hidden)]
pub fn register_tls_ops(ops: RtldTlsOps) {
    tls::register_ops(ops);
}

#[doc(hidden)]
pub fn tls_get_addr_soft(mod_id: TlsModuleId) -> *mut u8 {
    tls::tls_get_addr_soft(mod_id)
}

#[doc(hidden)]
pub fn new_loader() -> RuntimeLoader {
    ElfLoader::new()
        .with_data::<ExtraData>()
        .with_tls_resolver::<ActiveTlsResolver>()
        .with_static_tls(true)
}

#[doc(hidden)]
pub unsafe fn set_initial_process_state(
    argc: usize,
    argv: *const *const u8,
    envp: *const *const u8,
) {
    unsafe {
        ARGC = argc;
        ARGV = argv as *const *mut c_char;
        ENVP = envp as *const *const c_char;
    }
}

#[doc(hidden)]
pub fn register_loaded_object(raw: &ElfDylib, flags: OpenFlags) {
    let loaded = unsafe { LoadedDylib::from_core(raw.core()) };
    register_loaded(loaded, flags, &mut *crate::lock_write!(MANAGER));
}

#[doc(hidden)]
pub fn link_mapped_root(root_request: &str, raw: ElfDylib, flags: OpenFlags) -> Result<ElfLibrary> {
    let root_key = mapped_root_key(raw.name()).to_owned();
    log::info!(
        "dlopen: Link mapped root [{}] as [{}] with [{:?}]",
        root_request,
        root_key,
        flags
    );
    let ctx = OpenContext::new(flags);
    link_root(
        ctx,
        &root_key,
        LinkRoot::Mapped {
            key: root_key.clone(),
            raw,
        },
    )
}

fn mapped_root_key(name: &str) -> &str {
    if name.is_empty() {
        "main"
    } else {
        name.rsplit(|c| c == '/' || c == '\\')
            .next()
            .unwrap_or(name)
    }
}

#[doc(hidden)]
pub fn raw_link_map(raw: &ElfDylib) -> *mut link_map::LinkMap {
    extra_data_link_map(raw.user_data())
}

#[doc(hidden)]
pub unsafe fn handle_link_map(handle: *mut c_void) -> *mut link_map::LinkMap {
    let Some(library) = (unsafe { handle.cast::<ElfLibrary>().as_ref() }) else {
        return core::ptr::null_mut();
    };
    extra_data_link_map(library.inner.user_data())
}

#[doc(hidden)]
pub unsafe fn dladdr_raw(addr: *const c_void, info: *mut c_void) -> c_int {
    unsafe { crate::api::dladdr(addr, info.cast()) }
}

#[doc(hidden)]
pub struct StartupLinkMaps {
    pub maps: Box<[*mut link_map::LinkMap]>,
    pub libc_map: *mut link_map::LinkMap,
}

#[doc(hidden)]
pub fn startup_link_maps(library: &ElfLibrary, rtld: *mut link_map::LinkMap) -> StartupLinkMaps {
    let mut maps = Vec::with_capacity(library.deps.len() + 1);
    let mut libc_map = core::ptr::null_mut();
    let mut has_rtld = false;

    for dep in library.deps.iter() {
        let link_map = extra_data_link_map(dep.user_data());
        if link_map.is_null() {
            continue;
        }

        if link_map == rtld {
            has_rtld = true;
        }
        if dep.name() == "libc.so.6" {
            libc_map = link_map;
        }
        maps.push(link_map);
    }

    if !rtld.is_null() && !has_rtld {
        let insert_at = usize::from(!maps.is_empty());
        maps.insert(insert_at, rtld);
    }

    StartupLinkMaps {
        maps: maps.into_boxed_slice(),
        libc_map,
    }
}

fn extra_data_link_map(data: &ExtraData) -> *mut link_map::LinkMap {
    data.link_map
        .as_deref()
        .map_or(core::ptr::null_mut(), |link_map| {
            core::ptr::from_ref(link_map).cast_mut()
        })
}

#[doc(hidden)]
pub unsafe fn find_loaded_symbol<T: Copy>(name: &str) -> Option<T> {
    let manager = crate::lock_read!(MANAGER);
    manager
        .all_values()
        .find_map(|lib| unsafe { lib.get::<T>(name).map(|sym| *sym) })
}

mod tls {
    use elf_loader::{
        Result,
        arch::NativeArch,
        error::TlsError,
        memory::VmAddr,
        tls::{
            DefaultTlsResolver, TlsImageSource, TlsIndex, TlsInfo, TlsModuleId, TlsResolver,
            TlsTpOffset,
        },
    };
    use spin::Once;

    pub type ActiveTlsResolver = RtldTlsResolver;

    #[derive(Clone, Copy)]
    pub struct RtldTlsOps {
        pub register: fn(&TlsInfo) -> Result<TlsModuleId>,
        pub register_static: fn(&TlsInfo) -> Result<(TlsModuleId, TlsTpOffset)>,
        pub add_static_tls: fn(&TlsInfo, TlsTpOffset) -> Result<TlsModuleId>,
        pub init_tls: fn(TlsImageSource, TlsModuleId, Option<TlsTpOffset>) -> Result<()>,
        pub unregister: fn(TlsModuleId),
        pub tls_get_addr: extern "C" fn(*const TlsIndex) -> *mut u8,
        pub tls_get_addr_soft: fn(TlsModuleId) -> *mut u8,
    }

    static RTLD_TLS_OPS: Once<RtldTlsOps> = Once::new();

    pub(crate) fn register_ops(ops: RtldTlsOps) {
        RTLD_TLS_OPS.call_once(|| ops);
    }

    pub(crate) fn tls_get_addr_soft(mod_id: TlsModuleId) -> *mut u8 {
        if mod_id.is_reserved() {
            return core::ptr::null_mut();
        }
        if let Some(ops) = RTLD_TLS_OPS.get() {
            return (ops.tls_get_addr_soft)(mod_id);
        }
        DefaultTlsResolver::get_ptr(mod_id).unwrap_or(core::ptr::null_mut())
    }

    #[derive(Debug)]
    pub struct RtldTlsResolver;

    impl TlsResolver<NativeArch> for RtldTlsResolver {
        const OVERRIDE_TLS_GET_ADDR: bool = true;

        fn register(tls_info: &TlsInfo) -> Result<TlsModuleId> {
            if let Some(ops) = RTLD_TLS_OPS.get() {
                return (ops.register)(tls_info);
            }
            <DefaultTlsResolver as TlsResolver<NativeArch>>::register(tls_info)
        }

        fn register_static(tls_info: &TlsInfo) -> Result<(TlsModuleId, TlsTpOffset)> {
            if let Some(ops) = RTLD_TLS_OPS.get() {
                return (ops.register_static)(tls_info);
            }
            Err(TlsError::StaticResolverUnsupported.into())
        }

        fn add_static_tls(tls_info: &TlsInfo, offset: TlsTpOffset) -> Result<TlsModuleId> {
            if let Some(ops) = RTLD_TLS_OPS.get() {
                return (ops.add_static_tls)(tls_info, offset);
            }
            <DefaultTlsResolver as TlsResolver<NativeArch>>::add_static_tls(tls_info, offset)
        }

        fn init_tls(
            source: TlsImageSource,
            mod_id: TlsModuleId,
            offset: Option<TlsTpOffset>,
        ) -> Result<()> {
            if let Some(ops) = RTLD_TLS_OPS.get() {
                return (ops.init_tls)(source, mod_id, offset);
            }
            <DefaultTlsResolver as TlsResolver<NativeArch>>::init_tls(source, mod_id, offset)
        }

        fn unregister(mod_id: TlsModuleId) {
            if let Some(ops) = RTLD_TLS_OPS.get() {
                (ops.unregister)(mod_id);
                return;
            }
            <DefaultTlsResolver as TlsResolver<NativeArch>>::unregister(mod_id);
        }

        fn bind_tls_get_addr() -> Result<VmAddr> {
            if let Some(ops) = RTLD_TLS_OPS.get() {
                return Ok(VmAddr::from_ptr(ops.tls_get_addr as *const ()));
            }
            <DefaultTlsResolver as TlsResolver<NativeArch>>::bind_tls_get_addr()
        }

        fn resolve_tls_addr(ti: TlsIndex) -> Result<VmAddr> {
            if let Some(ops) = RTLD_TLS_OPS.get() {
                return Ok(VmAddr::from_ptr((ops.tls_get_addr)(&ti)));
            }
            <DefaultTlsResolver as TlsResolver<NativeArch>>::resolve_tls_addr(ti)
        }
    }
}
