use crate::abi::elf::ElfPhdr;
use core::ffi::c_void;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum BootstrapMode {
    KernelMappedMain,
    DirectExec,
}

#[derive(Copy, Clone)]
pub struct BootstrapObject {
    pub load_bias: usize,
    pub dynamic: *mut c_void,
    pub phdr: *const ElfPhdr,
    pub phnum: usize,
    pub entry: usize,
}

impl BootstrapObject {
    pub const fn zero() -> Self {
        Self {
            load_bias: 0,
            dynamic: core::ptr::null_mut(),
            phdr: core::ptr::null(),
            phnum: 0,
            entry: 0,
        }
    }
}

#[derive(Copy, Clone)]
pub struct BootstrapState {
    pub argc: usize,
    pub argv: *const *const u8,
    pub envp: *const *const u8,
    pub auxv: *const usize,
    pub mode: BootstrapMode,
    pub exec_path: *const u8,
    pub main: BootstrapObject,
    pub rtld: BootstrapObject,
}

impl BootstrapState {
    pub const fn zero() -> Self {
        Self {
            argc: 0,
            argv: core::ptr::null(),
            envp: core::ptr::null(),
            auxv: core::ptr::null(),
            mode: BootstrapMode::KernelMappedMain,
            exec_path: core::ptr::null(),
            main: BootstrapObject::zero(),
            rtld: BootstrapObject::zero(),
        }
    }
}
