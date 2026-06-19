use dlopen_rs::rtld::elf::ElfPhdr;

#[derive(Copy, Clone)]
pub(super) struct BootstrapObject {
    pub(super) load_bias: usize,
    pub(super) phdr: *const ElfPhdr,
    pub(super) phnum: usize,
    pub(super) entry: usize,
}

#[derive(Copy, Clone)]
pub(super) struct BootstrapState {
    pub(super) argc: usize,
    pub(super) argv: *const *const u8,
    pub(super) envp: *const *const u8,
    pub(super) auxv: *const usize,
    pub(super) exec_path: *const u8,
    pub(super) main: BootstrapObject,
    pub(super) rtld: BootstrapObject,
}
