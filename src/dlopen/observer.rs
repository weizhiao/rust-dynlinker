use crate::{
    OpenFlags,
    abi::link_map::LinkMap,
    library::{ActiveTlsResolver, ExtraData},
    runtime::{ARGC, ARGV, ENVP, debug::add_debug_link_map},
};
use alloc::{borrow::ToOwned, boxed::Box, ffi::CString, string::ToString};
use core::{
    ffi::{c_char, c_int},
    ptr::null,
};
use elf_loader::{
    arch::NativeArch,
    elf::{ElfDyn, ElfPhdr, ElfProgramType},
    memory::{HostRegion, RegionAccess, VmAddr},
    observer::{
        AfterDynamicLoadEvent, DynamicRelocatedEvent, LinkerObserver, LinkerRelocationEvent,
        LoadObserver, RelocationObserver,
    },
    relocation::LookupOrder,
    tls::TlsResolver,
};

pub(crate) struct DlopenObserver {
    flags: OpenFlags,
}

impl DlopenObserver {
    pub(crate) const fn new(flags: OpenFlags) -> Self {
        Self { flags }
    }
}

impl LinkerObserver<Option<ExtraData>, NativeArch, HostRegion, ActiveTlsResolver>
    for DlopenObserver
{
    fn on_relocation(
        &mut self,
        event: &mut LinkerRelocationEvent<
            Option<ExtraData>,
            NativeArch,
            HostRegion,
            ActiveTlsResolver,
        >,
    ) -> elf_loader::Result<()> {
        log::debug!("Planning relocation for dylib [{}]", event.raw().name());
        event.set_lookup_order(if self.flags.is_deepbind() {
            LookupOrder::LocalFirst
        } else {
            LookupOrder::GlobalFirst
        });
        if self.flags.is_now() {
            event.set_binding(elf_loader::relocation::BindingMode::Eager);
        }
        Ok(())
    }
}

impl LoadObserver<Option<ExtraData>> for DlopenObserver {
    fn on_after_dynamic_load<R: RegionAccess, Tls: TlsResolver<NativeArch>>(
        &mut self,
        mut event: AfterDynamicLoadEvent<'_, Option<ExtraData>, NativeArch, R, Tls>,
    ) -> elf_loader::Result<()> {
        let dylib = event.raw_mut();
        let name = dylib.name().to_string();
        let path = dylib.path().as_str().to_owned();
        let link_name = if path.is_empty() {
            name.as_str()
        } else {
            path.as_str()
        };
        let base = dylib.segments().base();
        let dynamic_ptr = dylib
            .phdrs()
            .iter()
            .find(|p: &&ElfPhdr| p.program_type() == ElfProgramType::DYNAMIC)
            .map(|p: &ElfPhdr| (base + p.p_vaddr()).as_mut_ptr::<ElfDyn>())
            .unwrap_or(core::ptr::null_mut());

        let phdrs = dylib.phdrs();
        let phdr = if phdrs.is_empty() {
            null()
        } else {
            phdrs.as_ptr().cast()
        };
        let phnum = phdrs.len().min(u16::MAX as usize) as u16;
        let entry = dylib.entry();
        let tls = dylib.tls();
        let tls_mod_id = tls.map(|tls| tls.mod_id().get());
        let tls_tp_offset = tls
            .and_then(|tls| tls.tp_offset())
            .map(|offset| offset.get());

        let c_name = CString::new(link_name).unwrap();
        let mut link_map = Box::new(LinkMap {
            l_addr: base.as_mut_ptr(),
            l_name: c_name.as_ptr(),
            l_ld: dynamic_ptr as *mut _,
            l_next: core::ptr::null_mut(),
            l_prev: core::ptr::null_mut(),
            l_phdr: phdr,
            l_entry: entry,
            l_phnum: phnum,
            ..LinkMap::zero()
        });
        populate_link_map_tls(&mut link_map, base, phdrs, tls_mod_id, tls_tp_offset);
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

fn populate_link_map_tls(
    link_map: &mut LinkMap,
    base: VmAddr,
    phdrs: &[ElfPhdr],
    tls_mod_id: Option<usize>,
    tls_tp_offset: Option<isize>,
) {
    let Some(mod_id) = tls_mod_id else { return };
    link_map.l_tls_modid = mod_id;
    link_map.l_tls_offset = tls_tp_offset.unwrap_or(0);
    let Some(tls) = phdrs
        .iter()
        .find(|phdr| phdr.program_type() == ElfProgramType::TLS)
    else {
        return;
    };
    link_map.l_tls_blocksize = tls.p_memsz();
    link_map.l_tls_align = tls.p_align();
    link_map.l_tls_firstbyte_offset = tls.p_vaddr().get() & tls.p_align().saturating_sub(1);
    link_map.l_tls_initimage_size = tls.p_filesz();
    if tls.p_filesz() != 0 {
        link_map.l_tls_initimage = (base + tls.p_vaddr()).as_mut_ptr();
    }
}
