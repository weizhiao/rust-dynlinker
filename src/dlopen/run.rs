use super::{ld_cache::LdCache, observer::DlopenObserver};
use crate::{
    OpenFlags, Result,
    library::{AsFilename, ElfLibrary, ExtraData, OpenedLibrary},
    registry::REGISTRY,
    runtime::ENVP,
};
use alloc::{borrow::ToOwned, boxed::Box, format};
use core::ffi::CStr;
use elf_loader::{
    Loader,
    input::{ElfBinary, Path, PathBuf as ElfPath},
    lazy::NativeLazyBinder,
    linker::{Linker, ModuleId, SearchPathResolver},
    memory::VmAddr,
    relocation::{BindingMode, LookupOrder, Relocator},
};
use spin::Lazy;

type DlopenLoader = Loader<Option<ExtraData>>;

pub(crate) enum LinkRoot<'bytes> {
    File(ElfPath),
    Binary {
        key: ElfPath,
        bytes: &'bytes [u8],
    },
    Mapped {
        key: alloc::vec::Vec<u8>,
        raw: Box<crate::library::ElfDylib>,
    },
}

fn loader() -> DlopenLoader {
    Loader::new().with_data::<Option<ExtraData>>()
}

static SEARCH_PATHS: Lazy<SearchPathResolver> = Lazy::new(|| {
    let mut resolver = SearchPathResolver::new();
    resolver.push_rpath();
    if let Some(paths) = get_env("LD_LIBRARY_PATH") {
        for path in paths
            .split(|byte| *byte == b':')
            .filter(|path| !path.is_empty())
        {
            resolver.push_fixed_dir(Path::new(path));
        }
    }
    resolver.push_runpath();
    let cache = LdCache::new().ok();
    resolver.push_candidate_provider(move |request, candidates| {
        if let Some(path) = cache
            .as_ref()
            .and_then(|cache| cache.lookup(request.requested().as_bytes()))
        {
            candidates.push(path);
        }
        Ok(())
    });
    push_platform_default_paths(&mut resolver);
    for path in ["/lib", "/usr/lib", "/lib64", "/usr/lib64"] {
        resolver.push_fixed_dir(Path::new(path));
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

pub(super) fn get_env(name: &str) -> Option<&'static [u8]> {
    unsafe {
        let mut cur = ENVP;
        if cur.is_null() {
            return None;
        }
        while !(*cur).is_null() {
            let env = CStr::from_ptr(*cur).to_bytes();
            if let Some(index) = env.iter().position(|byte| *byte == b'=')
                && &env[..index] == name.as_bytes()
            {
                return Some(&env[index + 1..]);
            }
            cur = cur.add(1);
        }
    }
    None
}

pub(crate) fn open_main() -> OpenedLibrary {
    let registry = REGISTRY.lock();
    registry
        .borrow_mut()
        .main_library()
        .expect("Main executable must be initialized")
}

#[cfg(not(feature = "std"))]
pub(crate) fn open_mapped(
    request: &Path,
    key: alloc::vec::Vec<u8>,
    raw: crate::library::ElfDylib,
    flags: OpenFlags,
    before_init: impl FnOnce(ModuleId) -> Result<()>,
) -> Result<OpenedLibrary> {
    open_with(
        request,
        flags,
        LinkRoot::Mapped {
            key,
            raw: Box::new(raw),
        },
        None,
        before_init,
    )
}

impl ElfLibrary {
    /// Get the main executable as an `ElfLibrary`. It is the same as `dlopen(NULL, RTLD_NOW)`.
    pub fn this() -> ElfLibrary {
        open_main().into()
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
        open(path, flags, LinkRoot::File(path.to_owned()), Some(caller)).map(ElfLibrary::from)
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
        open(
            path,
            flags,
            LinkRoot::Binary {
                key: path.to_owned(),
                bytes,
            },
            Some(caller),
        )
        .map(ElfLibrary::from)
    }
}

pub(crate) fn open<'bytes>(
    request: &Path,
    flags: OpenFlags,
    root: LinkRoot<'bytes>,
    caller: Option<usize>,
) -> Result<OpenedLibrary> {
    open_with(request, flags, root, caller, |_| Ok(()))
}

fn open_with<'bytes>(
    request: &Path,
    mut flags: OpenFlags,
    root: LinkRoot<'bytes>,
    caller: Option<usize>,
    before_init: impl FnOnce(ModuleId) -> Result<()>,
) -> Result<OpenedLibrary> {
    let registry = REGISTRY.lock();
    if get_env("LD_BIND_NOW").is_some() {
        flags |= OpenFlags::RTLD_NOW;
    }

    log::info!("dlopen: Try to open [{}] with [{:?}] ", request, flags);

    if matches!(root, LinkRoot::File(_) | LinkRoot::Binary { .. })
        && let Some(lib) = registry
            .borrow_mut()
            .open_existing(request.as_bytes(), flags)
    {
        log::info!(
            "dlopen: Reusing loaded library [{}] for request [{}]",
            lib.module().name().escape_ascii(),
            request
        );
        return Ok(lib);
    }
    if flags.is_noload() && matches!(root, LinkRoot::Binary { .. }) {
        return Err(crate::error::find_lib_error(format!(
            "can not find file: {request}"
        )));
    }

    let domain = registry.borrow_mut().context_mut().domain().clone();
    let loader = loader();
    let mut observer = DlopenObserver;
    let root = match root {
        LinkRoot::Binary { key, bytes } => {
            let raw = loader
                .run(domain)
                .with_observer(&mut observer)
                .load_dylib(ElfBinary::new(key.clone(), bytes))?;
            LinkRoot::Mapped {
                key: key.into_bytes(),
                raw: Box::new(raw.into()),
            }
        }
        root => root,
    };

    let linker = Linker::new()
        .with_loader(loader)
        .with_relocator(Relocator::new().with_lazy_binder(NativeLazyBinder::new()))
        .map_relocator(|relocator| {
            relocator.with_binding(if flags.is_now() {
                BindingMode::Eager
            } else {
                BindingMode::Default
            })
        })
        .with_resolver((*SEARCH_PATHS).clone());
    let mut manager = registry.borrow_mut();
    let caller = caller.and_then(|addr| {
        manager
            .context_mut()
            .address_at(VmAddr::new(addr))
            .map(|matched| matched.owner)
    });
    let mut linker_run = linker
        .run()
        .with_lookup_order(if flags.is_deepbind() {
            LookupOrder::LocalFirst
        } else {
            LookupOrder::GlobalFirst
        })
        .with_observer(observer)
        .with_caller(caller);
    let prepared = match root {
        LinkRoot::File(path) => {
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
            linker_run.prepare_mapped(manager.context_mut(), key.into(), *raw)
        }
    }?;
    drop(manager);
    let relocated = linker_run.relocate(prepared)?;

    let published = {
        let mut manager = registry.borrow_mut();
        relocated.publish(manager.context_mut())?
    };
    if let Err(error) = before_init(published.root()) {
        let rollback = {
            let mut manager = registry.borrow_mut();
            published.rollback(manager.context_mut())
        };
        return Err(rollback.err().map_or(error, Into::into));
    }
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
