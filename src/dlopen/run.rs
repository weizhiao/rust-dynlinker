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

const fn dlopen_loader() -> DlopenLoader {
    Loader::new()
        .with_data::<ExtraData>()
        .with_tls_resolver(ActiveTlsResolver::new())
}

const DLOPEN_LINKER: Linker<NativeArch, DlopenLoader, (), NativeLazyBinder, ActiveTlsResolver> =
    Linker::new()
        .loader(dlopen_loader())
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
    pub fn dlopen(path: impl AsFilename, flags: OpenFlags) -> Result<ElfLibrary> {
        let path = path.as_filename();
        dlopen_impl(path, flags, LinkRoot::File(path.to_owned()))
    }

    /// Load a shared library from bytes. It is the same as dlopen. However, it can also be used in the no_std environment,
    /// and it will look for dependent libraries in those manually opened dynamic libraries.
    pub fn dlopen_from_binary(
        bytes: &[u8],
        path: impl AsFilename,
        flags: OpenFlags,
    ) -> Result<ElfLibrary> {
        let path = path.as_filename();
        dlopen_impl(
            path,
            flags,
            LinkRoot::Binary {
                key: path.to_owned(),
                bytes,
            },
        )
    }
}

pub(crate) fn dlopen_impl<'bytes>(
    request: &str,
    mut flags: OpenFlags,
    root: LinkRoot<'bytes>,
) -> Result<ElfLibrary> {
    let registry = REGISTRY.lock();
    if get_env("LD_BIND_NOW").is_some() {
        flags |= OpenFlags::RTLD_NOW;
    }

    log::info!("dlopen: Try to open [{}] with [{:?}] ", request, flags);

    if matches!(root, LinkRoot::File(_) | LinkRoot::Binary { .. }) {
        let name = request.rsplit(['/', '\\']).next().unwrap_or(request);
        if let Some(lib) = registry.borrow_mut().open_existing(name, flags) {
            log::info!(
                "dlopen: Found existing library [{}] (canonical name: {})",
                request,
                lib.name()
            );
            return Ok(lib);
        }
        if flags.is_noload() {
            return Err(crate::error::find_lib_error(format!(
                "can not find file: {request}"
            )));
        }
    }

    let mut observer = DlopenObserver::new(flags);
    let root = match root {
        LinkRoot::Binary { key, bytes } => {
            let mapped_key = key.rsplit(['/', '\\']).next().unwrap_or(&key).to_owned();
            let loader = dlopen_loader();
            let raw = loader
                .run()
                .with_observer(&mut observer)
                .load_dylib(ElfBinary::owned(key, bytes.to_vec()))?;
            LinkRoot::Mapped {
                key: mapped_key,
                raw: raw.into(),
            }
        }
        root => root,
    };

    let linker = DLOPEN_LINKER.resolver((*SEARCH_PATHS).clone());
    let mut linker_run = linker.run().with_observer(observer);
    let prepared = {
        let mut manager = registry.borrow_mut();
        match root {
            LinkRoot::File(path) => {
                linker_run.prepare_load(manager.context_mut(), ElfPath::from(path))
            }
            LinkRoot::Binary { .. } => unreachable!("binary roots are mapped before linking"),
            LinkRoot::Mapped { key, raw } => {
                linker_run.prepare_mapped_root(manager.context_mut(), key.into(), raw)
            }
        }
    }?;
    let relocated = linker_run.relocate(prepared)?;

    let published = {
        let mut manager = registry.borrow_mut();
        relocated.publish(manager.context_mut())
    }?;
    {
        let mut manager = registry.borrow_mut();
        manager.prepare_init(published.root(), flags);
        manager.add_alias(
            published.root(),
            request.rsplit(['/', '\\']).next().unwrap_or(request),
        );
    }
    match published.initialize() {
        Ok(load) => {
            let library = {
                let mut manager = registry.borrow_mut();
                manager.commit_published(load.modules(), flags);
                manager
                    .open_module(load.root())
                    .expect("linked root module must be registered")
            };
            drop(registry.release_load(load));
            Ok(library)
        }
        Err(failed) => {
            let error = {
                let mut manager = registry.borrow_mut();
                failed.rollback(manager.context_mut())
            };
            Err(error.into())
        }
    }
}
