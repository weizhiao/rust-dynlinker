mod publish;
mod stack;
mod stage0;
mod stage1;
mod stage2;
mod state;

use crate::globals::publish_tls_static_info;
use dlopen_rs::rtld::elf::ElfHeader;

#[unsafe(no_mangle)]
pub extern "C" fn rtld_bootstrap(
    stack: *const usize,
    rtld_ehdr: *const ElfHeader,
    rtld_dynamic: *const usize,
) -> usize {
    let stage0 = stage0::stage0(stack, rtld_ehdr, rtld_dynamic);
    match stage1::stage1(&stage0) {
        Ok(entry) => finish_stage1(entry),
        Err(err) => stage2::stage2(&stage0, err),
    }
}

fn finish_stage1(entry: usize) -> usize {
    let (size, align) = crate::tls::static_info();
    unsafe { publish_tls_static_info(size, align) };
    entry
}
