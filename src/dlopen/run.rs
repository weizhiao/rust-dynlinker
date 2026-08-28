use super::{ld_cache::LdCache, observer::DlopenObserver};
use crate::{
    OpenFlags, Result,
    library::{ActiveTlsResolver, AsFilename, ElfLibrary, ExtraData},
    registry::REGISTRY,
    runtime::ENVP,
};
use alloc::{borrow::ToOwned, format, string::String};
use core::ffi::CStr;
use elf_loader::{
    Loader,
    arch::NativeArch,
    input::{ElfBinary, PathBuf as ElfPath},
    lazy::NativeLazyBinder,
    linker::{Linker, SearchPathResolver},
    memory::VmAddr,
    relocation::Relocator,
};
use spin::Lazy;

type DlopenLoader = Loader<ExtraData, ActiveTlsResolver>;

pub(crate) enum LinkRoot<'bytes> {
    File(String),
    Binary {
        key: String,
        bytes: &'bytes [u8],
    },
    Mapped {
        key: String,
        raw: crate::library::ElfDylib,
    },
}

const LOADER: DlopenLoader = Loader::new()
    .with_data::<ExtraData>()
    .with_tls_resolver(ActiveTlsResolver::new());

const LINKER: Linker<NativeArch, DlopenLoader, (), NativeLazyBinder, ActiveTlsResolver> =
    Linker::new()
        .loader(LOADER)
        .relocator(Relocator::new().lazy_binder(NativeLazyBinder::new()));

static LD_CACHE: Lazy<Option<LdCache>> = Lazy::new(|| LdCache::new().ok());

static SEARCH_PATHS: Lazy<SearchPathResolver> = Lazy::new(|| {
    let mut resolver = SearchPathResolver::new();
    resolver.push_rpath();
    if let Some(paths) = get_env("LD_LIBRARY_PATH") {
        for path in paths.split(':').filter(|path| !path.is_empty()) {
            resolver.push_fixed_dir(path);
        }
    }
    resolver.push_runpath();
    resolver.push_candidate_provider(|request, candidates| {
        if let Some(path) = LD_CACHE
            .as_ref()
            .and_then(|cache| cache.lookup(request.requested().as_str()))
        {
            candidates.push(path.into());
        }
        Ok(())
    });
    push_platform_default_paths(&mut resolver);
    for path in ["/lib", "/usr/lib", "/lib64", "/usr/lib64"] {
        resolver.push_fixed_dir(path);
    }
    resolver
});

#[cfg(target_arch = "x86_64")]
fn push_platform_default_paths(resolver: &mut SearchPathResolver) {
    resolver.push_fixed_dir("/lib/x86_64-linux-gnu");
    resolver.push_fixed_dir("/usr/lib/x86_64-linux-gnu");
}

#[cfg(target_arch = "aarch64")]
fn push_platform_default_paths(resolver: &mut SearchPathResolver) {
    resolver.push_fixed_dir("/lib/aarch64-linux-gnu");
    resolver.push_fixed_dir("/usr/lib/aarch64-linux-gnu");
}

#[cfg(target_arch = "riscv64")]
fn push_platform_default_paths(resolver: &mut SearchPathResolver) {
    resolver.push_fixed_dir("/lib/riscv64-linux-gnu");
    resolver.push_fixed_dir("/usr/lib/riscv64-linux-gnu");
}

#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "riscv64"
)))]
fn push_platform_default_paths(_resolver: &mut SearchPathResolver) {}

#[inline(always)]
fn caller_module_address() -> usize {
    let address: usize;
    unsafe {
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!("lea {}, [rip]", out(reg) address, options(nostack, nomem));
        #[cfg(target_arch = "aarch64")]
        core::arch::asm!("adr {}, .", out(reg) address, options(nostack, nomem));
        #[cfg(target_arch = "riscv64")]
        core::arch::asm!("auipc {}, 0", out(reg) address, options(nostack, nomem));
    }
    address
}

pub(super) fn get_env(name: &str) -> Option<&'static str> {
    unsafe {
        let mut cur = ENVP;
        if cur.is_null() {
            return None;
        }
        while !(*cur).is_null() {
            if let Ok(env) = CStr::from_ptr(*cur).to_str()
                && let Some((key, value)) = env.split_once('=')
                && key == name
            {
                return Some(value);
            }
            cur = cur.add(1);
        }
    }
    None
}

impl ElfLibrary {
    /// Get the main executable as an `ElfLibrary`. It is the same as `dlopen(NULL, RTLD_NOW)`.
    pub fn this() -> ElfLibrary {
        let registry = REGISTRY.lock();
        registry
            .borrow_mut()
            .main_library()
            .expect("Main executable must be initialized")
    }

    /// Load a shared library from a specified path. It is the same as dlopen.
    ///
    /// # Example
    /// ```no_run
    /// # use dlopen_rs::{ElfLibrary, OpenFlags};
    ///
    /// let path = "/path/to/library.so";
    /// let lib = ElfLibrary::dlopen(path, OpenFlags::RTLD_LOCAL).expect("Failed to load library");
    /// ```
    #[inline(always)]
    pub fn dlopen(path: impl AsFilename, flags: OpenFlags) -> Result<ElfLibrary> {
        let caller = caller_module_address();
        let path = path.as_filename();
        dlopen_impl(path, flags, LinkRoot::File(path.to_owned()), Some(caller))
    }

    pub(crate) fn dlopen_from(
        path: impl AsFilename,
        flags: OpenFlags,
        caller: usize,
    ) -> Result<ElfLibrary> {
        let path = path.as_filename();
        dlopen_impl(
            path,
            flags,
            LinkRoot::File(path.to_owned()),
            (caller != 0).then_some(caller),
        )
    }

    /// Load a shared library from bytes. It is the same as dlopen. However, it can also be used in the no_std environment,
    /// and it will look for dependent libraries in those manually opened dynamic libraries.
    #[inline(always)]
    pub fn dlopen_from_binary(
        bytes: &[u8],
        path: impl AsFilename,
        flags: OpenFlags,
    ) -> Result<ElfLibrary> {
        let caller = caller_module_address();
        let path = path.as_filename();
        dlopen_impl(
            path,
            flags,
            LinkRoot::Binary {
                key: path.to_owned(),
                bytes,
            },
            Some(caller),
        )
    }
}

pub(crate) fn dlopen_impl<'bytes>(
    request: &str,
    mut flags: OpenFlags,
    root: LinkRoot<'bytes>,
    caller: Option<usize>,
) -> Result<ElfLibrary> {
    let registry = REGISTRY.lock();
    if get_env("LD_BIND_NOW").is_some() {
        flags |= OpenFlags::RTLD_NOW;
    }

    log::info!("dlopen: Try to open [{}] with [{:?}] ", request, flags);

    if matches!(root, LinkRoot::File(_) | LinkRoot::Binary { .. }) {
        if let Some(lib) = registry.borrow_mut().open_existing(request, flags) {
            log::info!(
                "dlopen: Reusing loaded library [{}] for request [{}]",
                lib.name(),
                request
            );
            return Ok(lib);
        }
    }
    if flags.is_noload() && matches!(root, LinkRoot::Binary { .. }) {
        return Err(crate::error::find_lib_error(format!(
            "can not find file: {request}"
        )));
    }

    let mut observer = DlopenObserver::new(flags);
    let root = match root {
        LinkRoot::Binary { key, bytes } => {
            let raw = LOADER
                .run()
                .with_observer(&mut observer)
                .load_dylib(ElfBinary::owned(key.clone(), bytes.to_vec()))?;
            LinkRoot::Mapped {
                key,
                raw: raw.into(),
            }
        }
        root => root,
    };

    let linker = LINKER.resolver((*SEARCH_PATHS).clone());
    let mut manager = registry.borrow_mut();
    let caller = caller.and_then(|addr| manager.context_mut().module_id_at(VmAddr::new(addr)));
    let mut linker_run = linker.run().with_observer(observer).with_caller(caller);
    let prepared = match root {
        LinkRoot::File(path) => {
            let path = ElfPath::from(path);
            if flags.is_noload() {
                let id = linker_run
                    .resolve_committed(manager.context_mut(), path)?
                    .ok_or_else(|| {
                        crate::error::find_lib_error(format!("can not find file: {request}"))
                    })?;
                manager.promote(id, flags);
                return Ok(manager
                    .open_module(id)
                    .expect("resolved module must remain committed"));
            }
            linker_run.prepare_load(manager.context_mut(), path)
        }
        LinkRoot::Binary { .. } => unreachable!("binary roots are mapped before linking"),
        LinkRoot::Mapped { key, raw } => {
            linker_run.prepare_mapped(manager.context_mut(), key.into(), raw)
        }
    }?;
    drop(manager);
    let relocated = linker_run.relocate(prepared)?;

    let published = {
        let mut manager = registry.borrow_mut();
        relocated.publish(manager.context_mut())?
    };
    match published.initialize() {
        Ok(load) => Ok(registry.borrow_mut().open_load(load, flags)),
        Err(failed) => {
            let error = {
                let mut manager = registry.borrow_mut();
                failed.rollback(manager.context_mut())
            };
            Err(error.into())
        }
    }
}
