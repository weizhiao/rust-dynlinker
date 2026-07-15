use super::{
    context::{LinkRoot, OpenContext},
    ld_cache::LdCache,
    observer::DlopenObserver,
    resolver::LinkResolver,
};
use crate::{
    OpenFlags, Result,
    image::{ActiveTlsResolver, AsFilename, ElfLibrary, ExtraData},
    registry::REGISTRY,
    runtime::ENVP,
};
use alloc::{
    borrow::ToOwned,
    boxed::Box,
    rc::Rc,
    string::{String, ToString},
    vec::Vec,
};
use core::ffi::CStr;
use elf_loader::{
    Loader, arch::NativeArch, input::PathBuf as ElfPath, lazy::NativeLazyBinder, linker::Linker,
    relocation::Relocator,
};
use spin::Lazy;

type DlopenLoader = Loader<ExtraData, ActiveTlsResolver>;

const DLOPEN_LINKER: Linker<
    String,
    NativeArch,
    DlopenLoader,
    (),
    NativeLazyBinder,
    ActiveTlsResolver,
> = Linker::new()
    .loader(
        Loader::new()
            .with_data::<ExtraData>()
            .with_tls_resolver::<ActiveTlsResolver>(),
    )
    .relocator(Relocator::new().lazy_binder(NativeLazyBinder::new()));

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
        dlopen_impl(
            path,
            flags,
            LinkRoot::Load {
                key: path.to_owned(),
                bytes: None,
            },
        )
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
            LinkRoot::Load {
                key: path.to_owned(),
                bytes: Some(bytes),
            },
        )
    }
}

pub(crate) fn dlopen_impl<'bytes>(
    request: &str,
    flags: OpenFlags,
    root: LinkRoot<'bytes>,
) -> Result<ElfLibrary> {
    let registry = REGISTRY.lock();
    let ctx = OpenContext::new(flags);

    log::info!("dlopen: Try to open [{}] with [{:?}] ", request, ctx.flags);

    if root.reuse_existing()
        && let Some(lib) = ctx.try_existing(&registry, request)
    {
        return Ok(lib);
    }

    #[cfg(not(feature = "std"))]
    ctx.reserve_root_if_needed(&root);

    let key_resolver = LinkResolver::new(
        ctx.flags,
        registry.identity_lookup(),
        Rc::clone(&ctx.staged),
        root.key(),
        root.source(),
    );
    let linker = DLOPEN_LINKER.resolver(key_resolver);
    let mut linker_run = linker.run().with_observer(DlopenObserver::new(ctx.flags));
    let prepared = {
        let mut manager = registry.borrow_mut();
        match root {
            LinkRoot::Load { key, .. } => {
                linker_run.prepare_load::<_, str>(manager.context_mut(), key)
            }
            #[cfg(not(feature = "std"))]
            LinkRoot::Mapped { key, raw } => {
                linker_run.prepare_mapped_root::<_, str>(manager.context_mut(), key, raw)
            }
        }
    }?;
    let relocated = linker_run.relocate(prepared)?;

    let committed = {
        let mut manager = registry.borrow_mut();
        linker_run.commit(manager.context_mut(), relocated)
    }?;
    // Constructors may reenter dlopen, so register and retain the group before initialization.
    let library = ctx.register(&registry, committed.committed(), committed.root_id());
    match linker_run.initialize(committed) {
        Ok(load) => {
            registry.publish(load.committed());
            Ok(library)
        }
        Err(failed) => {
            let libraries = registry.rollback_committed(failed.committed());
            crate::registry::destroy_libraries(libraries);
            Err(failed.into_error().into())
        }
    }
}

pub(super) static LD_LIBRARY_PATH: Lazy<Box<[ElfPath]>> = Lazy::new(|| {
    if let Some(path) = get_env("LD_LIBRARY_PATH") {
        parse_path_list(path)
    } else {
        Box::new([])
    }
});

pub(super) static DEFAULT_PATH: Lazy<Box<[ElfPath]>> = Lazy::new(|| {
    let mut v = Vec::new();
    push_platform_default_paths(&mut v);
    v.push(ElfPath::from("/lib"));
    v.push(ElfPath::from("/usr/lib"));
    v.push(ElfPath::from("/lib64"));
    v.push(ElfPath::from("/usr/lib64"));
    v.into_boxed_slice()
});

pub(super) static LD_CACHE: Lazy<Option<LdCache>> = Lazy::new(|| LdCache::new().ok());

#[cfg(target_arch = "x86_64")]
fn push_platform_default_paths(paths: &mut Vec<ElfPath>) {
    paths.push(ElfPath::from("/lib/x86_64-linux-gnu"));
    paths.push(ElfPath::from("/usr/lib/x86_64-linux-gnu"));
}

#[cfg(target_arch = "aarch64")]
fn push_platform_default_paths(paths: &mut Vec<ElfPath>) {
    paths.push(ElfPath::from("/lib/aarch64-linux-gnu"));
    paths.push(ElfPath::from("/usr/lib/aarch64-linux-gnu"));
}

#[cfg(target_arch = "riscv64")]
fn push_platform_default_paths(paths: &mut Vec<ElfPath>) {
    paths.push(ElfPath::from("/lib/riscv64-linux-gnu"));
    paths.push(ElfPath::from("/usr/lib/riscv64-linux-gnu"));
}

#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "riscv64"
)))]
fn push_platform_default_paths(_paths: &mut Vec<ElfPath>) {}

#[inline]
pub(super) fn fixup_rpath(lib_path: &str, rpath: &str) -> Box<[ElfPath]> {
    if !rpath.contains('$') {
        return parse_path_list(rpath);
    }
    for s in rpath.split('$').skip(1) {
        if !s.starts_with("ORIGIN") && !s.starts_with("{ORIGIN}") {
            log::warn!("DT_RUNPATH format is incorrect: [{}]", rpath);
            return Box::new([]);
        }
    }
    let dir = if let Some((path, _)) = lib_path.rsplit_once('/') {
        path
    } else {
        "."
    };
    parse_path_list(&rpath.to_string().replace("$ORIGIN", dir))
}

/// Parses a colon-separated list of paths into a boxed slice of ElfPath.
#[inline]
fn parse_path_list(s: &str) -> Box<[ElfPath]> {
    s.split(':')
        .filter(|str| !str.is_empty())
        .map(ElfPath::from)
        .collect()
}

pub(super) fn should_continue_library_search(err: &crate::error::Error) -> bool {
    match err {
        #[cfg(feature = "std")]
        crate::error::Error::IO(err) => err.kind() == std::io::ErrorKind::NotFound,
        #[cfg(not(feature = "std"))]
        crate::error::Error::IO(msg) => {
            msg.contains("No such file")
                || msg.contains("ENOENT")
                || msg.contains("Failed to open file")
        }
        _ => false,
    }
}

#[inline]
pub(super) fn is_elf_input(bytes: &[u8]) -> bool {
    bytes.starts_with(b"\x7fELF")
}
