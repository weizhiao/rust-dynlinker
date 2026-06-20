use core::{ffi::c_int, ptr::null_mut};
use dlopen_rs::rtld::elf::ElfDynamicTag;

mod entry;

pub(crate) const DL_NNS: usize = 16;
pub(crate) const EXEC_PAGESIZE: usize = 4096;
pub(crate) const FPU_DEFAULT: u16 = 0x037f;
pub(crate) const PTHREAD_MUTEX_RECURSIVE_NP: c_int = 1;
pub(crate) const STDERR_FILENO: c_int = 2;

pub(crate) const X86_CPU_FEATURES_SIZE: usize = 528;

pub(crate) const NATIVE_RELOCATION_TAG: ElfDynamicTag = ElfDynamicTag::RELA;
pub(crate) const NATIVE_RELOCATION_SIZE_TAG: ElfDynamicTag = ElfDynamicTag::RELASZ;
pub(crate) const NATIVE_RELOCATION_ENTRY_SIZE_TAG: ElfDynamicTag = ElfDynamicTag::RELAENT;

pub(crate) fn install_thread_pointer(tp: *mut u8) -> bool {
    const ARCH_SET_FS: usize = 0x1002;
    let res = unsafe { syscalls::raw_syscall!(syscalls::Sysno::arch_prctl, ARCH_SET_FS, tp) };
    res <= -4096isize as usize
}

pub(crate) fn get_thread_pointer() -> *mut u8 {
    const ARCH_GET_FS: usize = 0x1003;
    let mut tp = 0usize;
    let res = unsafe {
        syscalls::raw_syscall!(
            syscalls::Sysno::arch_prctl,
            ARCH_GET_FS,
            &mut tp as *mut usize
        )
    };
    if res <= -4096isize as usize {
        tp as *mut u8
    } else {
        null_mut()
    }
}
