use alloc::string::String;
use core::{
    ffi::CStr,
    ptr::{addr_of_mut, null},
};

use super::{
    publish::{
        BootstrapObject, BootstrapState, publish_bootstrap_objects, publish_loaded_globals,
        publish_rtld_link_map,
    },
    stack::rewrite_initial_stack_for_program,
    stage0::Stage0,
    stage2::Stage1Failure,
};
use crate::{
    cli::handle_direct_invocation,
    globals::{__libc_stack_end, _dl_argv},
    runtime::{RTLD_FATAL_EXIT_STATUS, exit},
};
use dlopen_rs::{
    Error, OpenFlags, Result,
    rtld::{
        self,
        auxv::{AT_BASE, AT_ENTRY, AT_EXECFN, AT_NULL, AT_PHDR, AT_PHENT, AT_PHNUM},
        elf::ElfPhdr,
    },
};
use syscalls::Sysno;

const RTLD_NAME: &str = "ld-linux-x86-64.so.2";
const AT_FDCWD: usize = -100isize as usize;
const F_GETFD: usize = 1;
const O_RDONLY: usize = 0;
const O_WRONLY: usize = 1;
const O_NOFOLLOW: usize = 0o400000;

pub(super) fn stage1(stage0: &Stage0) -> core::result::Result<usize, Stage1Failure> {
    install_stage1_runtime(stage0.stack);

    if stage0.direct_invocation {
        let state = unsafe { publish_direct_exec_state(stage0) };
        unsafe { install_process_context(&state) };
        check_standard_fds_if_secure(stage0.aux.secure);
        return unsafe { prepare_direct_exec(&state) }.map_err(Stage1Failure::DirectExec);
    }

    let state = unsafe { publish_kernel_mapped_main_state(stage0) };
    unsafe { install_process_context(&state) };
    check_standard_fds_if_secure(stage0.aux.secure);
    unsafe { prepare_kernel_mapped_main(&state) }.map_err(Stage1Failure::KernelMappedMain)
}

fn install_stage1_runtime(stack: *const usize) {
    crate::tls::install_resolver_ops();
    unsafe { addr_of_mut!(__libc_stack_end).write(stack) };
}

unsafe fn install_process_context(state: &BootstrapState) {
    unsafe {
        addr_of_mut!(_dl_argv).write(state.argv);
        rtld::set_initial_process_state(state.argc, state.argv, state.envp);
    }
}

fn check_standard_fds_if_secure(secure: usize) {
    if secure == 0 {
        return;
    }

    check_standard_fd(0, b"/dev/full\0", O_WRONLY | O_NOFOLLOW);
    check_standard_fd(1, b"/dev/null\0", O_RDONLY | O_NOFOLLOW);
    check_standard_fd(2, b"/dev/null\0", O_RDONLY | O_NOFOLLOW);
}

fn check_standard_fd(fd: usize, path: &[u8], flags: usize) {
    if unsafe { syscalls::syscall2(Sysno::fcntl, fd, F_GETFD).is_ok() } {
        return;
    }

    let Ok(opened) =
        (unsafe { syscalls::syscall4(Sysno::openat, AT_FDCWD, path.as_ptr() as usize, flags, 0) })
    else {
        exit(RTLD_FATAL_EXIT_STATUS);
    };

    if opened != fd {
        exit(RTLD_FATAL_EXIT_STATUS);
    }
}

unsafe fn publish_direct_exec_state(stage0: &Stage0) -> BootstrapState {
    let direct = unsafe { handle_direct_invocation(stage0.argc, stage0.argv) };
    let rewritten = unsafe { rewrite_initial_stack_for_program(stage0.stack, stage0.argc, direct) };
    unsafe {
        publish_bootstrap_objects(
            rewritten.argc,
            rewritten.argv,
            rewritten.envp,
            rewritten.auxv,
            stage0.aux,
            0,
            null(),
            stage0.rtld_load_bias,
            stage0.rtld_dynamic,
            rewritten.exec_path,
        )
    }
}

unsafe fn publish_kernel_mapped_main_state(stage0: &Stage0) -> BootstrapState {
    unsafe {
        publish_bootstrap_objects(
            stage0.argc,
            stage0.argv,
            stage0.envp,
            stage0.auxv,
            stage0.aux,
            stage0.main_load_bias,
            stage0.main_dynamic,
            stage0.rtld_load_bias,
            stage0.rtld_dynamic,
            null(),
        )
    }
}

unsafe fn prepare_kernel_mapped_main(state: &BootstrapState) -> Result<usize> {
    let mut loader = rtld::new_loader();
    let rtld_link_map = unsafe { load_bootstrap_rtld(&mut loader, state.rtld)? };

    let main = unsafe { load_bootstrap_object(&mut loader, "", state.main)? };
    let entry = main.entry();
    unsafe { link_startup_root("", main, state, rtld_link_map)? };
    Ok(entry)
}

unsafe fn prepare_direct_exec(state: &BootstrapState) -> Result<usize> {
    let exec_path = unsafe { CStr::from_ptr(state.exec_path.cast()) }
        .to_str()
        .map_err(|_| Error::InvalidPath)?;
    let mut loader = rtld::new_loader();
    let rtld_link_map = unsafe { load_bootstrap_rtld(&mut loader, state.rtld)? };

    let exec = loader.load_exec(exec_path).map_err(Error::from)?;
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
        rtld::RawExec::Dynamic(dynamic) => unsafe {
            link_startup_root(exec_path, dynamic, state, rtld_link_map)?
        },
        rtld::RawExec::Static(static_exec) => {
            core::mem::forget(static_exec);
        }
    }
    Ok(entry)
}

unsafe fn load_bootstrap_rtld(
    loader: &mut rtld::RuntimeLoader,
    object: BootstrapObject,
) -> Result<*mut rtld::link_map::LinkMap> {
    let dylib = unsafe { load_bootstrap_object(loader, RTLD_NAME, object)? };
    let link_map = rtld::raw_link_map(&dylib);
    if link_map.is_null() {
        return Err(Error::FindLibError {
            msg: String::from("bootstrap rtld is missing link map"),
        });
    }
    rtld::register_loaded_object(&dylib, OpenFlags::RTLD_GLOBAL | OpenFlags::RTLD_NODELETE);
    Ok(link_map)
}

unsafe fn load_bootstrap_object(
    loader: &mut rtld::RuntimeLoader,
    name: impl Into<rtld::PathBuf>,
    object: BootstrapObject,
) -> Result<rtld::ElfDylib> {
    if object.phdr.is_null() || object.phnum == 0 {
        return Err(Error::FindLibError {
            msg: String::from("bootstrap object is missing program headers"),
        });
    }

    let phdrs = unsafe { core::slice::from_raw_parts(object.phdr, object.phnum) }.to_vec();
    unsafe {
        loader.load_mapped_dynamic(
            name,
            rtld::VmAddr::new(object.load_bias),
            phdrs,
            object.entry,
        )
    }
    .map_err(Into::into)
}

unsafe fn link_startup_root(
    root_request: &str,
    root: rtld::ElfDylib,
    state: &BootstrapState,
    rtld_link_map: *mut rtld::link_map::LinkMap,
) -> Result<()> {
    let main = rtld::raw_link_map(&root);
    if main.is_null() {
        return Err(Error::FindLibError {
            msg: String::from("startup root is missing link map"),
        });
    }

    let startup_flags = OpenFlags::RTLD_GLOBAL | OpenFlags::RTLD_NOW | OpenFlags::RTLD_NODELETE;
    let handle = rtld::link_mapped_root(root_request, root, startup_flags)?;
    let rtld = unsafe { publish_rtld_link_map(rtld_link_map) };
    let link_maps = rtld::startup_link_maps(&handle, rtld);
    unsafe { publish_loaded_globals(state, main, link_maps) };
    super::publish_tls_layout();
    unsafe { call_libc_early_init() };
    drop(handle);
    Ok(())
}

unsafe fn call_libc_early_init() {
    type EarlyInit = unsafe extern "C" fn(bool);
    let Some(init) = (unsafe { rtld::find_loaded_symbol::<EarlyInit>("__libc_early_init") }) else {
        return;
    };
    unsafe { init(true) };
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
