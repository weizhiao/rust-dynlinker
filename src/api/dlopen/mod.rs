mod context;
mod planner;
mod resolver;

pub(crate) use context::{LinkRoot, OpenContext};

use self::{
    planner::DlopenPlanner,
    resolver::{DlopenVisible, LinkResolver},
};
use crate::{
    OpenFlags, Result,
    core_impl::{
        ActiveTlsResolver, AsFilename, DlopenObserver, DylibExt, ENVP, ElfLibrary, ExtraData,
        MANAGER,
    },
    error::find_lib_error,
    utils::ld_cache::LdCache,
};
use alloc::{
    borrow::ToOwned,
    boxed::Box,
    format,
    string::{String, ToString},
    vec::Vec,
};
use core::ffi::{CStr, c_char, c_int, c_void};
use elf_loader::input::PathBuf as ElfPath;
use elf_loader::linker::{LinkContext, Linker};
use spin::Lazy;

fn get_env(name: &str) -> Option<&'static str> {
    unsafe {
        let mut cur = ENVP;
        if cur.is_null() {
            return None;
        }
        while !(*cur).is_null() {
            if let Ok(env) = CStr::from_ptr(*cur).to_str() {
                if let Some((k, v)) = env.split_once('=') {
                    if k == name {
                        return Some(v);
                    }
                }
            }
            cur = cur.add(1);
        }
    }
    None
}

impl ElfLibrary {
    /// Get the main executable as an `ElfLibrary`. It is the same as `dlopen(NULL, RTLD_NOW)`.
    pub fn this() -> ElfLibrary {
        let reader = crate::lock_read!(MANAGER);
        reader
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
        dlopen_impl(path.as_filename(), flags, None)
    }

    /// Load a shared library from bytes. It is the same as dlopen. However, it can also be used in the no_std environment,
    /// and it will look for dependent libraries in those manually opened dynamic libraries.
    pub fn dlopen_from_binary(
        bytes: &[u8],
        path: impl AsFilename,
        flags: OpenFlags,
    ) -> Result<ElfLibrary> {
        dlopen_impl(path.as_filename(), flags, Some(bytes))
    }
}

pub(crate) fn link_root<'mgr, 'bytes>(
    mut ctx: OpenContext<'mgr>,
    root_request: &str,
    root: LinkRoot<'bytes>,
) -> Result<ElfLibrary> {
    #[cfg(not(feature = "std"))]
    ctx.reserve_root_if_needed(&root);

    let key_resolver = LinkResolver::new(
        &ctx.shared,
        &mut ctx.added_names,
        root_request,
        root.source(),
    );
    let visible_modules = DlopenVisible::new(&ctx.shared);
    let mut link_ctx = LinkContext::new();
    let relocation_planner = DlopenPlanner::new(&ctx.shared);
    let mut linker = Linker::<String>::new()
        .map_loader(|loader| {
            loader
                .with_data::<ExtraData>()
                .with_observer(DlopenObserver)
                .with_tls_resolver::<ActiveTlsResolver>()
        })
        .map_relocator(|relocator| relocator.observer(DlopenObserver))
        .visible_modules(visible_modules)
        .resolver(key_resolver)
        .planner(relocation_planner);
    let load_result = match root {
        LinkRoot::Load { key, .. } => linker.load(&mut link_ctx, key)?,
        #[cfg(not(feature = "std"))]
        LinkRoot::Mapped { key, raw } => linker.load_mapped_root(&mut link_ctx, key, raw)?,
    };
    drop(linker);

    let root_shortname = load_result.root().shortname().to_owned();
    ctx.complete_relocation(&link_ctx, load_result.committed().iter().copied());

    drop(link_ctx);

    let deps = ctx.library_scope(&root_shortname);
    Ok(ctx.finish(deps))
}

fn dlopen_impl(path: &str, flags: OpenFlags, bytes: Option<&[u8]>) -> Result<ElfLibrary> {
    let mut ctx = OpenContext::new(flags);

    log::info!(
        "dlopen: Try to open [{}] with [{:?}] ",
        path,
        ctx.shared.flags
    );

    if let Some(lib) = ctx.try_existing(path) {
        return Ok(lib);
    }

    if ctx.shared.flags.is_noload() {
        return Err(find_lib_error(format!("can not find file: {}", path)));
    }

    link_root(
        ctx,
        path,
        LinkRoot::Load {
            key: path.to_owned(),
            bytes,
        },
    )
}

static LD_LIBRARY_PATH: Lazy<Box<[ElfPath]>> = Lazy::new(|| {
    if let Some(path) = get_env("LD_LIBRARY_PATH") {
        parse_path_list(path)
    } else {
        Box::new([])
    }
});
static DEFAULT_PATH: Lazy<Box<[ElfPath]>> = Lazy::new(|| {
    let mut v = Vec::new();
    push_platform_default_paths(&mut v);
    v.push(ElfPath::from("/lib"));
    v.push(ElfPath::from("/usr/lib"));
    v.push(ElfPath::from("/lib64"));
    v.push(ElfPath::from("/usr/lib64"));
    v.into_boxed_slice()
});
static LD_CACHE: Lazy<Option<LdCache>> = Lazy::new(|| LdCache::new().ok());

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
fn fixup_rpath(lib_path: &str, rpath: &str) -> Box<[ElfPath]> {
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

fn should_continue_library_search(err: &crate::error::Error) -> bool {
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
fn is_elf_input(bytes: &[u8]) -> bool {
    bytes.starts_with(b"\x7fELF")
}

/// # Safety
/// It is the same as `dlopen`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dlopen(filename: *const c_char, flags: c_int) -> *const c_void {
    let lib = if filename.is_null() {
        ElfLibrary::this()
    } else {
        let flags = OpenFlags::from_bits_retain(flags as _);
        let filename = unsafe { CStr::from_ptr(filename) };
        let Ok(path) = filename.to_str() else {
            return core::ptr::null();
        };
        if let Ok(lib) = ElfLibrary::dlopen(path, flags) {
            lib
        } else {
            return core::ptr::null();
        }
    };
    Box::into_raw(Box::new(lib)) as _
}
