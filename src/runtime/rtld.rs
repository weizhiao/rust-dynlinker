pub use crate::abi::{auxv, debug, elf, link_map, memory, relocation};

use crate::{
    OpenFlags, Result,
    dlopen::{DlopenObserver, open_mapped},
    library::{ExtraData, LoadedDylib, NativeElfModule},
    registry::REGISTRY,
    runtime::{ARGC, ARGV, ENVP},
};
use alloc::{borrow::ToOwned, boxed::Box, vec::Vec};
use core::ffi::{c_char, c_void};
use elf_loader::{Loader as ElfLoader, linker::ModuleId};
use spin::Mutex;

type RuntimeLoader = ElfLoader<Option<ExtraData>, ActiveTlsResolver>;

static STARTUP_ROOT: Mutex<Option<ModuleId>> = Mutex::new(None);

#[doc(hidden)]
pub use self::tls::{ActiveTlsResolver, RtldTlsOps};
#[doc(hidden)]
pub use crate::library::ElfDylib;
#[doc(hidden)]
pub use elf_loader::{
    Result as ElfResult,
    arch::NativeArch,
    error::TlsError,
    image::RawExec,
    input::PathBuf,
    memory::VmAddr,
    tls::{TlsImageSource, TlsIndex, TlsInfo, TlsModuleId, TlsRequest, TlsTpOffset},
};

#[doc(hidden)]
pub fn register_tls_ops(ops: RtldTlsOps) {
    tls::register_ops(ops);
}

#[doc(hidden)]
pub fn tls_get_addr_soft(mod_id: TlsModuleId) -> *mut u8 {
    tls::tls_get_addr_soft(mod_id)
}

fn loader() -> RuntimeLoader {
    ElfLoader::new()
        .with_data::<Option<ExtraData>>()
        .with_tls_resolver(ActiveTlsResolver::default())
        .with_static_tls(true)
}

#[doc(hidden)]
pub fn load_exec(
    path: &str,
) -> ElfResult<
    RawExec<Option<ExtraData>, NativeArch, elf_loader::memory::HostRegion, ActiveTlsResolver>,
> {
    let mut observer = DlopenObserver::new(OpenFlags::empty());
    loader().run().with_observer(&mut observer).load_exec(path)
}

/// # Safety
///
/// The mapped image must satisfy the requirements of
/// [`elf_loader::loader::LoaderRun::load_mapped_dynamic`].
#[doc(hidden)]
pub unsafe fn load_mapped(
    path: PathBuf,
    load_bias: VmAddr,
    phdrs: Vec<elf::ElfPhdr>,
    entry: usize,
) -> ElfResult<ElfDylib> {
    let mut observer = DlopenObserver::new(OpenFlags::empty());
    unsafe {
        loader()
            .run()
            .with_observer(&mut observer)
            .load_mapped_dynamic(path, load_bias, phdrs, entry)
    }
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
pub fn register_loaded(raw: &ElfDylib, flags: OpenFlags) -> Result<*mut link_map::LinkMap> {
    let link_map = raw
        .user_data()
        .as_ref()
        .map(ExtraData::link_map)
        .ok_or_else(|| crate::error::find_lib_error("loaded object is missing link map"))?;
    let registry = REGISTRY.lock();
    let loaded = unsafe { LoadedDylib::from_core((**raw).clone()) };
    registry.borrow_mut().register_loaded(loaded, flags);
    Ok(link_map)
}

#[doc(hidden)]
pub fn link_mapped_root(
    root_request: &str,
    raw: ElfDylib,
    flags: OpenFlags,
    rtld: *mut link_map::LinkMap,
    before_init: impl FnOnce(StartupState) -> Result<()>,
) -> Result<()> {
    let name = raw.name();
    let root_key = if name.is_empty() {
        "main"
    } else {
        name.rsplit(['/', '\\']).next().unwrap_or(name)
    }
    .to_owned();
    let mut startup_root = None;
    let opened = open_mapped(root_request, root_key, raw, flags, |root| {
        startup_root = Some(root);
        let state = startup_state(root, rtld)?;
        before_init(state)
    })?;
    *STARTUP_ROOT.lock() = startup_root;
    drop(opened);
    Ok(())
}

#[doc(hidden)]
pub unsafe fn handle_link_map(handle: *mut c_void) -> *mut link_map::LinkMap {
    crate::registry::handle_link_map(handle as usize).unwrap_or(core::ptr::null_mut())
}

#[doc(hidden)]
pub struct StartupState {
    pub main: *mut link_map::LinkMap,
    pub maps: Box<[*mut link_map::LinkMap]>,
    pub libc_map: *mut link_map::LinkMap,
}

fn startup_state(root: ModuleId, rtld: *mut link_map::LinkMap) -> Result<StartupState> {
    let registry = REGISTRY.lock();
    let mut manager = registry.borrow_mut();
    manager.context_mut().promote_global(root)?;
    manager.register_initial_aliases();
    let scope = manager.context_mut().load_group(root)?;
    let main = scope
        .first()
        .and_then(|module| module.downcast_ref::<NativeElfModule>())
        .and_then(|module| module.user_data().as_ref())
        .map(ExtraData::link_map)
        .ok_or_else(|| crate::error::find_lib_error("startup root is missing link map"))?;
    let mut maps = Vec::with_capacity(scope.len() + 1);
    let mut libc_map = core::ptr::null_mut();

    for dep in scope.iter() {
        let Some(dep) = dep.downcast_ref::<NativeElfModule>() else {
            continue;
        };
        let link_map = dep
            .user_data()
            .as_ref()
            .expect("loaded dependency must have extra data")
            .link_map();

        if dep.name() == "libc.so.6" {
            libc_map = link_map;
        }
        let is_rtld = link_map == rtld
            || (!rtld.is_null()
                && unsafe { core::ptr::addr_eq((*link_map).l_addr, (*rtld).l_addr) });
        if is_rtld {
            continue;
        }
        maps.push(link_map);
    }

    if !rtld.is_null() {
        let insert_at = usize::from(!maps.is_empty());
        maps.insert(insert_at, rtld);
    }

    Ok(StartupState {
        main,
        maps: maps.into_boxed_slice(),
        libc_map,
    })
}

#[doc(hidden)]
pub fn finalize_startup() {
    let Some(root) = STARTUP_ROOT.lock().take() else {
        return;
    };
    let scope = {
        let registry = REGISTRY.lock();
        let mut manager = registry.borrow_mut();
        manager.context_mut().load_group(root).ok()
    };
    let Some(scope) = scope else {
        return;
    };
    for module in scope.iter() {
        let module = module.as_ref();
        let _ = module.state().finalize(|| module.finalize());
    }
}

#[doc(hidden)]
pub unsafe fn find_loaded_symbol<T: Copy>(name: &str) -> Option<T> {
    let registry = REGISTRY.lock();
    let manager = registry.borrow();
    manager
        .all_values()
        .find_map(|lib| unsafe { lib.get::<T>(name).map(|sym| *sym) })
}

mod tls {
    use alloc::vec::Vec;
    use elf_loader::{
        Result,
        arch::NativeArch,
        memory::VmAddr,
        tls::{
            DefaultTlsResolver, ModuleTls, TlsImageSource, TlsIndex, TlsInfo, TlsModuleId,
            TlsRequest, TlsResolver, TlsTpOffset,
        },
    };
    use spin::{Mutex, Once};

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
    static TLS_MODULES: Mutex<Vec<(TlsModuleId, Option<TlsTpOffset>)>> = Mutex::new(Vec::new());

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

    #[derive(Clone, Copy, Debug, Default)]
    pub struct RtldTlsResolver;

    impl RtldTlsResolver {
        pub const fn new() -> Self {
            Self
        }
    }

    impl TlsResolver<NativeArch> for RtldTlsResolver {
        const OVERRIDE_TLS_GET_ADDR: bool = true;

        fn register(&self, info: TlsInfo, request: TlsRequest) -> Result<ModuleTls> {
            let Some(ops) = RTLD_TLS_OPS.get() else {
                return DefaultTlsResolver::new().register(info, request);
            };
            let module = match request {
                TlsRequest::Dynamic => ModuleTls::Dynamic {
                    mod_id: (ops.register)(&info)?,
                },
                TlsRequest::Static(None) => {
                    let (mod_id, tp_offset) = (ops.register_static)(&info)?;
                    ModuleTls::Static { mod_id, tp_offset }
                }
                TlsRequest::Static(Some(tp_offset)) => ModuleTls::Static {
                    mod_id: (ops.add_static_tls)(&info, tp_offset)?,
                    tp_offset,
                },
            };
            TLS_MODULES
                .lock()
                .push((module.mod_id(), module.tp_offset()));
            Ok(module)
        }

        fn publish(&self, source: TlsImageSource, mod_id: TlsModuleId) -> Result<()> {
            let Some(ops) = RTLD_TLS_OPS.get() else {
                return DefaultTlsResolver::new().publish(source, mod_id);
            };
            let offset = TLS_MODULES
                .lock()
                .iter()
                .find(|(id, _)| *id == mod_id)
                .and_then(|(_, offset)| *offset);
            (ops.init_tls)(source, mod_id, offset)
        }

        fn unregister(&self, mod_id: TlsModuleId) {
            if let Some(ops) = RTLD_TLS_OPS.get() {
                TLS_MODULES.lock().retain(|(id, _)| *id != mod_id);
                (ops.unregister)(mod_id);
                return;
            }
            DefaultTlsResolver::new().unregister(mod_id);
        }

        fn bind_tls_get_addr(&self) -> Result<VmAddr> {
            if let Some(ops) = RTLD_TLS_OPS.get() {
                return Ok(VmAddr::from_ptr(ops.tls_get_addr as *const ()));
            }
            DefaultTlsResolver::new().bind_tls_get_addr()
        }
    }
}
