pub use crate::abi::{auxv, debug, elf, memory, relocation};

use crate::{
    OpenFlags, Result,
    api::dlopen::{LinkRoot, OpenContext, link_root},
    core_impl::{
        ARGC, ARGV, ENVP, ElfLibrary, LoadedDylib, MANAGER, register_loaded, shortname_from_name,
    },
};
use alloc::borrow::ToOwned;
use core::ffi::c_char;

#[doc(hidden)]
pub use self::tls::{ActiveTlsResolver, RtldTlsOps};
#[doc(hidden)]
pub use crate::core_impl::{DlopenObserver, ElfDylib, ExtraData, RuntimeLoader};
#[doc(hidden)]
pub use elf_loader::{
    Loader as ElfLoader, Result as ElfResult, TlsError,
    image::RawExec,
    input::PathBuf,
    memory::VmAddr,
    tls::{DefaultTlsResolver, TlsIndex, TlsInfo, TlsModuleId, TlsResolver, TlsTpOffset},
};

#[doc(hidden)]
pub fn register_tls_ops(ops: RtldTlsOps) {
    tls::register_ops(ops);
}

#[doc(hidden)]
pub fn new_loader() -> RuntimeLoader {
    ElfLoader::new()
        .with_data::<ExtraData>()
        .with_observer(DlopenObserver)
        .with_tls_resolver::<ActiveTlsResolver>()
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
    let root_key = shortname_from_name(raw.name()).to_owned();
    log::info!(
        "dlopen: Link mapped root [{}] as [{}] with [{:?}]",
        root_request,
        root_key,
        flags
    );
    let ctx = OpenContext::new(flags);
    link_root(ctx, root_request, LinkRoot::Mapped { key: root_key, raw })
}

#[doc(hidden)]
pub unsafe fn refresh_static_tls() {
    unsafe { tls::refresh_static_tls() };
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
        Result, TlsError,
        tls::{DefaultTlsResolver, TlsIndex, TlsInfo, TlsModuleId, TlsResolver, TlsTpOffset},
    };
    use spin::Once;

    pub type ActiveTlsResolver = RtldTlsResolver;

    #[derive(Clone, Copy)]
    pub struct RtldTlsOps {
        pub register_static: fn(&TlsInfo) -> Result<(TlsModuleId, TlsTpOffset)>,
        pub refresh_static_tls: unsafe fn(),
    }

    static RTLD_TLS_OPS: Once<RtldTlsOps> = Once::new();

    pub(crate) fn register_ops(ops: RtldTlsOps) {
        RTLD_TLS_OPS.call_once(|| ops);
    }

    pub(crate) unsafe fn refresh_static_tls() {
        let Some(ops) = RTLD_TLS_OPS.get() else {
            return;
        };
        unsafe { (ops.refresh_static_tls)() };
    }

    #[derive(Debug)]
    pub struct RtldTlsResolver;

    impl TlsResolver for RtldTlsResolver {
        fn register(tls_info: &TlsInfo) -> Result<TlsModuleId> {
            <DefaultTlsResolver as TlsResolver>::register(tls_info)
        }

        fn register_static(tls_info: &TlsInfo) -> Result<(TlsModuleId, TlsTpOffset)> {
            let Some(ops) = RTLD_TLS_OPS.get() else {
                return Err(TlsError::StaticResolverUnsupported.into());
            };
            (ops.register_static)(tls_info)
        }

        fn add_static_tls(tls_info: &TlsInfo, offset: TlsTpOffset) -> Result<TlsModuleId> {
            <DefaultTlsResolver as TlsResolver>::add_static_tls(tls_info, offset)
        }

        fn unregister(mod_id: TlsModuleId) {
            <DefaultTlsResolver as TlsResolver>::unregister(mod_id);
        }

        extern "C" fn tls_get_addr(ti: *const TlsIndex) -> *mut u8 {
            <DefaultTlsResolver as TlsResolver>::tls_get_addr(ti)
        }
    }
}
