use alloc::string::String;
use core::{
    ffi::CStr,
    ptr::{addr_of_mut, null},
};

use super::{
    publish::publish_bootstrap_objects,
    stack::rewrite_initial_stack_for_program,
    stage0::Stage0,
    stage2::Stage1Failure,
    state::{BootstrapObject, BootstrapState},
};
use crate::{
    cli::handle_direct_invocation,
    globals::{__libc_stack_end, _dl_argv},
};
use dlopen_rs::{
    Error, OpenFlags, Result,
    rtld::{
        self,
        auxv::{AT_BASE, AT_ENTRY, AT_EXECFN, AT_NULL, AT_PHDR, AT_PHENT, AT_PHNUM},
        elf::ElfPhdr,
    },
};

const RTLD_NAME: &str = "ld-linux-x86-64.so.2";

pub(super) fn stage1(stage0: &Stage0) -> core::result::Result<usize, Stage1Failure> {
    install_stage1_context(stage0);

    if stage0.direct_invocation {
        let state = unsafe { publish_direct_exec_state(stage0) };
        return unsafe { prepare_direct_exec(&state) }.map_err(Stage1Failure::DirectExec);
    }

    let state = unsafe { publish_kernel_mapped_main_state(stage0) };
    unsafe { prepare_kernel_mapped_main(&state) }.map_err(Stage1Failure::KernelMappedMain)
}

fn install_stage1_context(stage0: &Stage0) {
    crate::tls::install_resolver_ops();
    unsafe {
        addr_of_mut!(_dl_argv).write(stage0.argv);
        addr_of_mut!(__libc_stack_end).write(stage0.stack);
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
    unsafe { rtld::set_initial_process_state(state.argc, state.argv, state.envp) };

    let mut loader = rtld::new_loader();
    let rtld_dylib = unsafe { load_bootstrap_object(&mut loader, RTLD_NAME, state.rtld)? };
    rtld::register_loaded_object(
        &rtld_dylib,
        OpenFlags::RTLD_GLOBAL | OpenFlags::RTLD_NODELETE,
    );

    let main = unsafe { load_bootstrap_object(&mut loader, "", state.main)? };
    let entry = main.entry();
    unsafe { link_startup_root("", main)? };
    Ok(entry)
}

unsafe fn prepare_direct_exec(state: &BootstrapState) -> Result<usize> {
    unsafe { rtld::set_initial_process_state(state.argc, state.argv, state.envp) };

    let exec_path = unsafe { CStr::from_ptr(state.exec_path.cast()) }
        .to_str()
        .map_err(|_| Error::InvalidPath)?;
    let mut loader = rtld::new_loader();
    let rtld_dylib = unsafe { load_bootstrap_object(&mut loader, RTLD_NAME, state.rtld)? };
    rtld::register_loaded_object(
        &rtld_dylib,
        OpenFlags::RTLD_GLOBAL | OpenFlags::RTLD_NODELETE,
    );

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
        rtld::RawExec::Dynamic(dynamic) => unsafe { link_startup_root(exec_path, dynamic)? },
        rtld::RawExec::Static(static_exec) => {
            core::mem::forget(static_exec);
        }
    }
    Ok(entry)
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

unsafe fn link_startup_root(root_request: &str, root: rtld::ElfDylib) -> Result<()> {
    let startup_flags = OpenFlags::RTLD_GLOBAL | OpenFlags::RTLD_NOW | OpenFlags::RTLD_NODELETE;
    let handle = rtld::link_mapped_root(root_request, root, startup_flags)?;
    unsafe { rtld::refresh_static_tls() };
    unsafe { run_glibc_startup_hooks() };
    drop(handle);
    Ok(())
}

unsafe fn run_glibc_startup_hooks() {
    unsafe { call_libc_early_init() };
    unsafe { call_libc_ctype_init() };
}

unsafe fn call_libc_early_init() {
    type EarlyInit = unsafe extern "C" fn(bool);
    let Some(init) = (unsafe { rtld::find_loaded_symbol::<EarlyInit>("__libc_early_init") }) else {
        return;
    };
    unsafe { init(true) };
}

unsafe fn call_libc_ctype_init() {
    type CtypeInit = unsafe extern "C" fn();
    let Some(init) = (unsafe { rtld::find_loaded_symbol::<CtypeInit>("__ctype_init") }) else {
        return;
    };
    unsafe { init() };
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
