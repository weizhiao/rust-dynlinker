use crate::{
    abi::link_map::LinkMap,
    library::{ActiveTlsResolver, ExtraData},
    runtime::{ARGC, ARGV, ENVP, debug::add_debug_link_map},
};
use alloc::{boxed::Box, ffi::CString};
use core::{
    ffi::{c_char, c_int},
    ptr::null,
};
use elf_loader::{
    arch::NativeArch,
    elf::ElfProgramType,
    memory::{HostRegion, RegionAccess},
    observer::{
        AfterDynamicLoadEvent, DynamicRelocatedEvent, LinkerObserver, LoadObserver,
        RelocationObserver,
    },
    tls::TlsResolver,
};

pub(crate) struct DlopenObserver;

impl LinkerObserver<Option<ExtraData>, NativeArch, HostRegion, ActiveTlsResolver>
    for DlopenObserver
{
}

impl LoadObserver<Option<ExtraData>> for DlopenObserver {
    fn on_after_dynamic_load<R: RegionAccess, Tls: TlsResolver<NativeArch>>(
        &mut self,
        mut event: AfterDynamicLoadEvent<'_, Option<ExtraData>, NativeArch, R, Tls>,
    ) -> elf_loader::Result<()> {
        let dylib = event.raw_mut();
        let base = dylib.segments().base();
        let phdrs = dylib.phdrs();
        let tls_phdr = phdrs
            .iter()
            .find(|phdr| phdr.program_type() == ElfProgramType::TLS);
        let phdr = if phdrs.is_empty() {
            null()
        } else {
            phdrs.as_ptr().cast()
        };
        let phnum = phdrs.len().min(u16::MAX as usize) as u16;
        let entry = dylib.entry();

        let c_name = CString::new(dylib.path().as_bytes()).unwrap();
        let mut link_map = Box::new(LinkMap {
            l_addr: base.as_mut_ptr(),
            l_name: c_name.as_ptr(),
            l_ld: dylib.dynamic_addr().as_mut_ptr(),
            l_next: core::ptr::null_mut(),
            l_prev: core::ptr::null_mut(),
            l_phdr: phdr,
            l_entry: entry,
            l_phnum: phnum,
            ..LinkMap::zero()
        });
        link_map.init_tls(base, tls_phdr, dylib.tls().map(|tls| tls.binding()));
        link_map.l_real = link_map.as_mut() as *mut LinkMap;

        unsafe { add_debug_link_map(link_map.as_mut()) };
        let user_data = dylib.user_data_mut().unwrap();
        *user_data = Some(ExtraData::new(c_name, link_map));
        Ok(())
    }
}

impl RelocationObserver for DlopenObserver {
    fn on_dynamic_relocated<
        D: Send + Sync + 'static,
        R: RegionAccess,
        Tls: TlsResolver<NativeArch>,
    >(
        &mut self,
        event: &mut DynamicRelocatedEvent<'_, D, NativeArch, R, Tls>,
    ) -> elf_loader::Result<()> {
        let lifecycle = event.lifecycle_mut();
        lifecycle.set_init_hook(|event| {
            let argc = unsafe { *core::ptr::addr_of!(ARGC) };
            let argv = unsafe { *core::ptr::addr_of!(ARGV) };
            let envp = unsafe { *core::ptr::addr_of!(ENVP) as *const *mut c_char };
            type InitFn = unsafe extern "C" fn(c_int, *const *mut c_char, *const *mut c_char);
            for init in event.lifecycle().func_addrs() {
                let init: InitFn = unsafe { core::mem::transmute(init) };
                unsafe { init(argc as c_int, argv, envp) };
            }
            event.lifecycle_mut().clear();
            Ok(())
        });
        Ok(())
    }
}
