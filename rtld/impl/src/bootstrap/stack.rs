use crate::{cli::DirectProgram, runtime::read_usize};
use dlopen_rs::rtld::auxv::AT_NULL;

pub(super) struct RewrittenStack {
    pub(super) argc: usize,
    pub(super) argv: *const *const u8,
    pub(super) envp: *const *const u8,
    pub(super) auxv: *const usize,
    pub(super) exec_path: *const u8,
}

pub(super) unsafe fn rewrite_initial_stack_for_program(
    stack: *const usize,
    argc: usize,
    direct: DirectProgram,
) -> RewrittenStack {
    let new_argc = argc.wrapping_sub(direct.argv_index);
    let src = unsafe { stack.add(1 + direct.argv_index) };
    let dst = unsafe { stack.add(1) as *mut usize };
    let old_envp = unsafe { stack.add(argc.wrapping_add(2)) };
    let mut old_auxv = old_envp;
    while unsafe { read_usize(old_auxv) } != 0 {
        old_auxv = unsafe { old_auxv.add(1) };
    }
    old_auxv = unsafe { old_auxv.add(1) };
    let mut old_end = old_auxv;
    while unsafe { read_usize(old_end) } != AT_NULL {
        old_end = unsafe { old_end.add(2) };
    }
    old_end = unsafe { old_end.add(2) };

    let count = (old_end as usize - src as usize) / core::mem::size_of::<usize>();
    let mut index = 0usize;
    while index < count {
        let value = unsafe { read_usize(src.add(index)) };
        unsafe { dst.add(index).write(value) };
        index = index.wrapping_add(1);
    }

    unsafe { (stack as *mut usize).write(new_argc) };
    let exec_path = unsafe { read_usize(dst) as *const u8 };
    if !direct.argv0.is_null() {
        unsafe { dst.write(direct.argv0 as usize) };
    }

    let argv = unsafe { stack.add(1) as *const *const u8 };
    let envp = unsafe { stack.add(new_argc.wrapping_add(2)) as *const *const u8 };
    let mut auxv = envp as *const usize;
    while unsafe { read_usize(auxv) } != 0 {
        auxv = unsafe { auxv.add(1) };
    }
    auxv = unsafe { auxv.add(1) };

    RewrittenStack {
        argc: new_argc,
        argv,
        envp,
        auxv,
        exec_path,
    }
}
