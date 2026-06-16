pub use crate::abi::{auxv, debug, elf};

use crate::abi::{
    auxv::{AT_BASE, AT_ENTRY, AT_EXECFN, AT_NULL, AT_PHDR, AT_PHENT, AT_PHNUM},
    elf::ElfPhdr,
};
use crate::{
    OpenFlags, Result,
    api::dlopen::{LinkRoot, OpenContext, link_root},
    core_impl::{
        ARGC, ARGV, DlopenObserver, ENVP, ElfDylib, ElfLibrary, ExtraData, LoadedDylib, MANAGER,
        RuntimeLoader, register_loaded, shortname_from_name,
    },
    error::find_lib_error,
};
use alloc::borrow::ToOwned;
use core::ffi::{CStr, c_char, c_void};
use elf_loader::{Loader, image::RawExec, input::PathBuf, memory::VmAddr};

use self::bootstrap::{BootstrapMode, BootstrapObject, BootstrapState};

const RTLD_NAME: &str = "ld-linux-x86-64.so.2";

pub(crate) use self::tls::ActiveTlsResolver;
pub use self::tls::RtldTlsBackend;

/// Runs the replacement rtld stage-1 startup path.
///
/// # Safety
///
/// `state` must describe live mapped objects that remain mapped while stage-1
/// performs relocation and registration.
pub unsafe fn stage1(state: &BootstrapState) -> Result<usize> {
    if state.mode == BootstrapMode::DirectExec {
        return unsafe { prepare_direct_exec(state) };
    }

    unsafe { prepare_kernel_mapped_main(state) }
}

fn dlopen_mapped_root(root_request: &str, raw: ElfDylib, flags: OpenFlags) -> Result<ElfLibrary> {
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

pub fn register_tls_backend(backend: RtldTlsBackend) {
    tls::register_backend(backend);
}

pub extern "C" fn tls_get_addr(index: *const usize) -> *mut c_void {
    tls::get_addr(index)
}

pub fn tls_static_info() -> (usize, usize) {
    tls::static_info()
}

pub unsafe fn tls_allocate(storage: *mut c_void) -> *mut c_void {
    unsafe { tls::allocate(storage.cast()).cast() }
}

pub unsafe fn tls_init(storage: *mut c_void) -> *mut c_void {
    unsafe { tls::init(storage.cast()).cast() }
}

pub unsafe fn tls_deallocate(storage: *mut c_void, dealloc_tcb: bool) {
    unsafe { tls::deallocate(storage.cast(), dealloc_tcb) };
}

pub mod bootstrap;
mod tls;

unsafe fn prepare_kernel_mapped_main(state: &BootstrapState) -> Result<usize> {
    unsafe {
        ARGC = state.argc;
        ARGV = state.argv as *const *mut c_char;
        ENVP = state.envp as *const *const c_char;
    }

    let mut loader = Loader::new()
        .with_data::<ExtraData>()
        .with_observer(DlopenObserver)
        .with_tls_resolver::<ActiveTlsResolver>();
    let rtld = unsafe { load_borrowed(&mut loader, RTLD_NAME, state.rtld)? };
    let rtld = unsafe { LoadedDylib::from_core(rtld.core()) };
    register_loaded(
        rtld,
        OpenFlags::RTLD_GLOBAL | OpenFlags::RTLD_NODELETE,
        &mut *crate::lock_write!(MANAGER),
    );

    let main = unsafe { load_borrowed(&mut loader, "", state.main)? };
    let entry = main.entry();
    let startup_flags = OpenFlags::RTLD_GLOBAL | OpenFlags::RTLD_NOW | OpenFlags::RTLD_NODELETE;
    let root_request = if state.exec_path.is_null() {
        ""
    } else {
        unsafe { CStr::from_ptr(state.exec_path.cast()) }
            .to_str()
            .unwrap_or("")
    };
    let handle = dlopen_mapped_root(root_request, main, startup_flags)?;
    unsafe { tls::refresh_static_tls() };
    unsafe { run_glibc_startup_hooks() };
    drop(handle);
    Ok(entry)
}

unsafe fn prepare_direct_exec(state: &BootstrapState) -> Result<usize> {
    unsafe {
        ARGC = state.argc;
        ARGV = state.argv as *const *mut c_char;
        ENVP = state.envp as *const *const c_char;
    }

    let exec_path = unsafe { CStr::from_ptr(state.exec_path.cast()) }
        .to_str()
        .map_err(|_| find_lib_error("direct exec path is not utf-8"))?;
    let mut loader = Loader::new()
        .with_data::<ExtraData>()
        .with_observer(DlopenObserver)
        .with_tls_resolver::<ActiveTlsResolver>();
    let rtld = unsafe { load_borrowed(&mut loader, RTLD_NAME, state.rtld)? };
    let rtld = unsafe { LoadedDylib::from_core(rtld.core()) };
    register_loaded(
        rtld,
        OpenFlags::RTLD_GLOBAL | OpenFlags::RTLD_NODELETE,
        &mut *crate::lock_write!(MANAGER),
    );

    let exec = loader.load_exec(exec_path)?;
    let (phdr, phnum) = exec
        .phdrs()
        .map(|phdrs| (phdrs.as_ptr() as usize, phdrs.len()))
        .unwrap_or((0, 0));
    let entry = exec.entry();
    unsafe {
        patch_exec_auxv(
            state.auxv as *mut usize,
            phdr,
            core::mem::size_of::<ElfPhdr>(),
            phnum,
            state.rtld.load_bias,
            entry,
            state.exec_path,
        );
    }

    match exec {
        RawExec::Dynamic(dynamic) => {
            let startup_flags =
                OpenFlags::RTLD_GLOBAL | OpenFlags::RTLD_NOW | OpenFlags::RTLD_NODELETE;
            let handle = dlopen_mapped_root(exec_path, dynamic, startup_flags)?;
            unsafe { tls::refresh_static_tls() };
            unsafe { run_glibc_startup_hooks() };
            drop(handle);
            Ok(entry)
        }
        RawExec::Static(exec) => {
            core::mem::forget(exec);
            Ok(entry)
        }
    }
}

unsafe fn load_borrowed(
    loader: &mut RuntimeLoader,
    name: impl Into<PathBuf>,
    object: BootstrapObject,
) -> Result<ElfDylib> {
    if object.phdr.is_null() || object.phnum == 0 {
        return Err(find_lib_error(
            "bootstrap object is missing program headers",
        ));
    }

    let phdrs = unsafe { core::slice::from_raw_parts(object.phdr, object.phnum) }.to_vec();
    unsafe { loader.load_mapped_dynamic(name, VmAddr::new(object.load_bias), phdrs, object.entry) }
        .map_err(Into::into)
}

unsafe fn run_glibc_startup_hooks() {
    unsafe { call_libc_early_init() };
    unsafe { call_libc_ctype_init() };
}

unsafe fn call_libc_early_init() {
    type EarlyInit = unsafe extern "C" fn(bool);
    let Some(init) = (unsafe { find_loaded_symbol::<EarlyInit>("__libc_early_init") }) else {
        return;
    };
    unsafe { init(true) };
}

unsafe fn call_libc_ctype_init() {
    type CtypeInit = unsafe extern "C" fn();
    let Some(init) = (unsafe { find_loaded_symbol::<CtypeInit>("__ctype_init") }) else {
        return;
    };
    unsafe { init() };
}

unsafe fn find_loaded_symbol<T: Copy>(name: &str) -> Option<T> {
    let manager = crate::lock_read!(MANAGER);
    manager
        .all_values()
        .find_map(|lib| unsafe { lib.get::<T>(name).map(|sym| *sym) })
}

unsafe fn patch_exec_auxv(
    mut auxv: *mut usize,
    phdr: usize,
    phent: usize,
    phnum: usize,
    base: usize,
    entry: usize,
    exec_path: *const u8,
) {
    if auxv.is_null() {
        return;
    }

    loop {
        let kind = unsafe { auxv.read() };
        if kind == AT_NULL {
            return;
        }
        let value = unsafe { auxv.add(1) };
        match kind {
            AT_PHDR => unsafe { value.write(phdr) },
            AT_PHENT => unsafe { value.write(phent) },
            AT_PHNUM => unsafe { value.write(phnum) },
            AT_BASE => unsafe { value.write(base) },
            AT_ENTRY => unsafe { value.write(entry) },
            AT_EXECFN => unsafe { value.write(exec_path as usize) },
            _ => {}
        }
        auxv = unsafe { auxv.add(2) };
    }
}
