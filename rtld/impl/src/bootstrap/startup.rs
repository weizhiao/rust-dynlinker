use alloc::string::String;
use core::{ffi::CStr, ptr::addr_of_mut};

use super::{
    publish::{BootstrapObject, BootstrapState, publish_bootstrap_state, publish_loaded_globals},
    self_reloc,
    stack::{InitialStack, patch_auxv},
};
use crate::{
    cli::handle_direct_invocation,
    globals::{__libc_stack_end, _dl_argv},
    runtime::{RTLD_FATAL_EXIT_STATUS, exit},
};
use dlopen_rs::{
    Error, OpenFlags, Result,
    rtld::{self, elf::ElfHeader},
};
use syscalls::Sysno;

const RTLD_NAME: &str = "ld-linux-x86-64.so.2";
const AT_FDCWD: usize = -100isize as usize;
const F_GETFD: usize = 1;
const O_RDONLY: usize = 0;
const O_WRONLY: usize = 1;
const O_NOFOLLOW: usize = 0o400000;

#[derive(Copy, Clone)]
pub(super) struct StartupInput {
    initial: InitialStack,
    main_load_bias: usize,
    main_dynamic: *const usize,
    rtld_load_bias: usize,
    direct: bool,
}

impl StartupInput {
    pub(super) fn new(
        stack: *const usize,
        rtld_ehdr: *const ElfHeader,
        rtld_dynamic: *const usize,
    ) -> Self {
        let rtld_load_bias = rtld_ehdr as usize;
        if !unsafe { self_reloc::relocate(rtld_dynamic, rtld_load_bias) } {
            exit(RTLD_FATAL_EXIT_STATUS);
        }

        let initial = unsafe { InitialStack::parse(stack) };
        let main_load_bias = initial.aux.load_bias();
        let main_dynamic = initial.aux.dynamic(main_load_bias);
        let direct = initial.aux.base == 0 || main_dynamic == rtld_dynamic;
        Self {
            initial,
            main_load_bias,
            main_dynamic,
            rtld_load_bias,
            direct,
        }
    }

    pub(super) fn pass_through_entry(self) -> Option<usize> {
        (!self.direct
            && self.initial.aux.entry != 0
            && !self.initial.aux.has_tls()
            && unsafe { self_reloc::can_pass_through(self.main_dynamic) })
        .then_some(self.initial.aux.entry)
    }

    pub(super) const fn is_direct(self) -> bool {
        self.direct
    }
}

pub(super) fn run(input: &StartupInput) -> Result<usize> {
    crate::tls::install_resolver_ops();
    unsafe { addr_of_mut!(__libc_stack_end).write(input.initial.raw) };

    let state = if input.direct {
        let process = input.initial.process;
        let direct = unsafe { handle_direct_invocation(process.argc, process.argv) };
        let process = unsafe { input.initial.rewrite_for_program(direct) };
        unsafe { publish_bootstrap_state(process, input.initial.aux, 0, input.rtld_load_bias) }
    } else {
        unsafe {
            publish_bootstrap_state(
                input.initial.process,
                input.initial.aux,
                input.main_load_bias,
                input.rtld_load_bias,
            )
        }
    };
    unsafe {
        addr_of_mut!(_dl_argv).write(state.process.argv);
        rtld::set_initial_process_state(state.process.argc, state.process.argv, state.process.envp);
    }
    check_standard_fds_if_secure(input.initial.aux.secure);

    let rtld_object = unsafe { load_bootstrap_object(RTLD_NAME, state.rtld)? };
    let rtld_link_map = rtld::register_loaded(
        &rtld_object,
        OpenFlags::RTLD_GLOBAL | OpenFlags::RTLD_NODELETE,
    )?;
    if input.direct {
        unsafe { prepare_direct_exec(&state, rtld_link_map) }
    } else {
        unsafe { prepare_kernel_mapped_main(&state, rtld_link_map) }
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

unsafe fn prepare_kernel_mapped_main(
    state: &BootstrapState,
    rtld_link_map: *mut rtld::link_map::LinkMap,
) -> Result<usize> {
    let main = unsafe { load_bootstrap_object("", state.main)? };
    let entry = main.entry();
    unsafe { link_startup_root("", main, state, rtld_link_map)? };
    Ok(entry)
}

unsafe fn prepare_direct_exec(
    state: &BootstrapState,
    rtld_link_map: *mut rtld::link_map::LinkMap,
) -> Result<usize> {
    let exec_path = unsafe { CStr::from_ptr(state.process.exec_path.cast()) }
        .to_str()
        .map_err(|_| Error::FindLibError {
            msg: String::from("executable path is not valid UTF-8"),
        })?;
    let exec = rtld::load_exec(exec_path).map_err(Error::from)?;
    let (phdr, phnum) = exec
        .phdrs()
        .map(|phdrs| (phdrs.as_ptr() as usize, phdrs.len()))
        .unwrap_or((0, 0));
    let entry = exec.entry();
    unsafe {
        patch_auxv(
            state.process.auxv as *mut usize,
            phdr,
            phnum,
            state.rtld.load_bias,
            entry,
            state.process.exec_path,
        );
    }

    match exec {
        rtld::RawExec::Dynamic(dynamic) => unsafe {
            link_startup_root(exec_path, dynamic, state, rtld_link_map)?
        },
        rtld::RawExec::Static(static_exec) => {
            super::publish_tls_layout();
            core::mem::forget(static_exec);
        }
    }
    Ok(entry)
}

unsafe fn load_bootstrap_object(
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
        rtld::load_mapped(
            name.into(),
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
    let startup_flags = OpenFlags::RTLD_GLOBAL | OpenFlags::RTLD_NOW | OpenFlags::RTLD_NODELETE;
    unsafe {
        (*rtld_link_map).l_next = core::ptr::null_mut();
        (*rtld_link_map).l_prev = core::ptr::null_mut();
        (*rtld_link_map).l_real = rtld_link_map;
    }
    rtld::link_mapped_root(
        root_request,
        root,
        startup_flags,
        rtld_link_map,
        |startup| {
            unsafe { publish_loaded_globals(state, startup.main, startup) };
            super::publish_tls_layout();
            type EarlyInit = unsafe extern "C" fn(bool);
            if let Some(init) =
                unsafe { rtld::find_loaded_symbol::<EarlyInit>("__libc_early_init") }
            {
                unsafe { init(true) };
            }
            Ok(())
        },
    )
}
