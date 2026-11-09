use super::{default_library_paths, observer::DlopenObserver};
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
    input::{ElfBinary, Path},
    lazy::NativeLazyBinder,
    linker::{LdCache, Linker, ModuleId, SearchPathResolver},
    memory::VmAddr,
    relocation::{BindingMode, LookupOrder, Relocator},
};
use spin::Once;

type DlopenLoader = Loader<Option<ExtraData>>;

pub(crate) enum LinkRoot<'bytes> {
    File,
    Binary(&'bytes [u8]),
    Mapped {
        key: alloc::vec::Vec<u8>,
        raw: Box<crate::library::ElfDylib>,
    },
}

fn loader() -> DlopenLoader {
    Loader::new().with_data::<Option<ExtraData>>()
}

static SEARCH_PATHS: Once<SearchPathResolver> = Once::new();

fn search_paths(executable: Option<&Path>) -> &'static SearchPathResolver {
    SEARCH_PATHS.call_once(|| {
        let library_path = get_env("LD_LIBRARY_PATH");
        let executable_dir = library_path
            .filter(|paths| contains_origin(paths))
            .and_then(|_| crate::os::executable_dir(executable));
        let mut resolver = SearchPathResolver::new();
        resolver.push_rpath();
        if let Some(paths) = library_path {
            if executable_dir.is_none() && contains_origin(paths) {
                // An empty origin would turn "$ORIGIN/lib" into "/lib". Omit only
                // those components when the executable directory is unavailable.
                for path in paths.split(|byte| matches!(byte, b':' | b';')) {
                    if contains_origin(path) {
                        continue;
                    }
                    resolver.push_library_path(
                        Path::new(if path.is_empty() { b".".as_slice() } else { path }),
                        Path::new(""),
                    );
                }
            } else {
                resolver.push_library_path(
                    Path::new(paths),
                    executable_dir.as_deref().unwrap_or_else(|| Path::new("")),
                );
            }
        }
        resolver.push_runpath();
        if let Ok(cache) = LdCache::load_system() {
            resolver.push_ld_cache(cache);
        }
        for dir in default_library_paths() {
            resolver.push_fixed_dir(dir);
        }
        resolver
    })
}

fn contains_origin(path: &[u8]) -> bool {
    path.split(|byte| *byte == b'$').skip(1).any(|token| {
        token.starts_with(b"{ORIGIN}")
            || token.strip_prefix(b"ORIGIN").is_some_and(|rest| {
                rest.first()
                    .is_none_or(|byte| !byte.is_ascii_alphanumeric() && *byte != b'_')
            })
    })
}

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
    search_paths((!request.as_bytes().is_empty()).then_some(request));
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
        open(path, flags, LinkRoot::File, Some(caller)).map(ElfLibrary::from)
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
        open(path, flags, LinkRoot::Binary(bytes), Some(caller)).map(ElfLibrary::from)
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

    if matches!(root, LinkRoot::File | LinkRoot::Binary(_))
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
    if flags.is_noload() && matches!(root, LinkRoot::Binary(_)) {
        return Err(crate::error::find_lib_error(format!(
            "can not find file: {request}"
        )));
    }

    let domain = registry.borrow().context().domain().clone();
    let loader = loader();
    let mut observer = DlopenObserver;
    let root = match root {
        LinkRoot::Binary(bytes) => {
            let raw = loader
                .run(domain)
                .with_observer(&mut observer)
                .load_dylib(ElfBinary::new(request, bytes))?;
            LinkRoot::Mapped {
                key: request.as_bytes().to_owned(),
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
        .with_resolver(search_paths(None).clone());
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
        LinkRoot::File => {
            if flags.is_noload() {
                let id = linker_run
                    .resolve_committed(manager.context_mut(), request.to_owned())?
                    .ok_or_else(|| {
                        crate::error::find_lib_error(format!("can not find file: {request}"))
                    })?;
                manager.promote(id, flags);
                return Ok(manager
                    .open_module(id)
                    .expect("resolved module must remain committed"));
            }
            linker_run.prepare_load(manager.context_mut(), request.to_owned())
        }
        LinkRoot::Binary(_) => unreachable!("binary roots are mapped before linking"),
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
