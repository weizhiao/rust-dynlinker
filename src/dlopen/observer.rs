use crate::{
    OpenFlags,
    abi::link_map::LinkMap,
    image::{ActiveTlsResolver, ExtraData},
    registry::REGISTRY,
    runtime::{ARGC, ARGV, ENVP, debug::add_debug_link_map},
};
use alloc::{
    borrow::ToOwned,
    boxed::Box,
    collections::BTreeSet,
    ffi::CString,
    string::{String, ToString},
    vec::Vec,
};
use core::{
    any::Any,
    ffi::{c_char, c_int},
    ptr::null,
    sync::atomic::Ordering,
};
use elf_loader::{
    arch::NativeArch,
    elf::{ElfDyn, ElfPhdr, ElfProgramType},
    image::{ModuleHandle, ModuleScope, ModuleScopeBuilder},
    memory::{HostRegion, RegionAccess, VmAddr},
    observer::{
        AfterDynamicLoadEvent, DynamicRelocatedEvent, LinkerObserver, LinkerRelocationEvent,
        LoadObserver, RelocationObserver,
    },
    tls::TlsResolver,
};

#[derive(Clone)]
pub(crate) struct DlopenObserver {
    flags: OpenFlags,
    scope: Option<ModuleScope<NativeArch, ActiveTlsResolver>>,
}

impl DlopenObserver {
    pub(crate) const fn new(flags: OpenFlags) -> Self {
        Self { flags, scope: None }
    }
}

impl LinkerObserver<String, ExtraData, NativeArch, HostRegion, ActiveTlsResolver>
    for DlopenObserver
{
    fn on_relocation(
        &mut self,
        event: &mut LinkerRelocationEvent<ExtraData, NativeArch, HostRegion, ActiveTlsResolver>,
    ) -> elf_loader::Result<()> {
        log::debug!("Planning relocation for dylib [{}]", event.raw().name());

        let group_scope = event.scope();
        let deepbind = self.flags.is_deepbind();
        let scope = self
            .scope
            .get_or_insert_with(|| {
                let registry = REGISTRY.lock();
                let manager = registry.borrow();
                let mut seen = BTreeSet::new();
                let mut modules = Vec::with_capacity(group_scope.len());
                let mut push_unique = |module: ModuleHandle<NativeArch, ActiveTlsResolver>| {
                    if seen.insert(module.name().to_owned()) {
                        modules.push(module);
                    }
                };
                if deepbind {
                    group_scope.iter().cloned().for_each(&mut push_unique);
                    manager
                        .global_values()
                        .map(Into::into)
                        .for_each(push_unique);
                } else {
                    manager
                        .global_values()
                        .map(Into::into)
                        .for_each(&mut push_unique);
                    group_scope.iter().cloned().for_each(push_unique);
                }

                let mut scope = ModuleScopeBuilder::new();
                scope.extend(modules);
                scope.into_scope()
            })
            .clone();
        event.set_scope(scope);
        if self.flags.is_now() {
            event.set_binding(elf_loader::relocation::BindingMode::Eager);
        } else if self.flags.is_lazy() {
            event.set_binding(elf_loader::relocation::BindingMode::Lazy);
        }
        Ok(())
    }
}

impl LoadObserver<ExtraData> for DlopenObserver {
    fn on_after_dynamic_load<R: RegionAccess, Tls: TlsResolver<NativeArch>>(
        &mut self,
        mut event: AfterDynamicLoadEvent<'_, ExtraData, NativeArch, R, Tls>,
    ) -> elf_loader::Result<()> {
        let dylib = event.raw_mut();
        let needed_libs = dylib
            .needed_libs()
            .iter()
            .map(|s: &&str| s.to_string())
            .collect::<Vec<_>>();

        let name = dylib.name().to_string();
        let path = dylib.path().as_str().to_owned();
        let link_name = if path.is_empty() {
            name.as_str()
        } else {
            path.as_str()
        };
        let base = dylib.base();
        let dynamic_ptr = dylib
            .phdrs()
            .iter()
            .find(|p: &&ElfPhdr| p.program_type() == ElfProgramType::DYNAMIC)
            .map(|p: &ElfPhdr| (base + p.p_vaddr()).as_mut_ptr::<ElfDyn>())
            .unwrap_or(core::ptr::null_mut());

        let phdrs = dylib.phdrs();
        #[cfg(feature = "std")]
        let mapped_range = {
            let start = phdrs
                .iter()
                .filter(|phdr| phdr.program_type() == ElfProgramType::LOAD)
                .map(|phdr| (base + phdr.p_vaddr()).get())
                .min();
            let end = phdrs
                .iter()
                .filter(|phdr| phdr.program_type() == ElfProgramType::LOAD)
                .map(|phdr| (base + phdr.p_vaddr()).get() + phdr.p_memsz())
                .max();
            start.zip(end)
        };
        let phdr = if phdrs.is_empty() {
            null()
        } else {
            phdrs.as_ptr().cast()
        };
        let phnum = phdrs.len().min(u16::MAX as usize) as u16;
        let entry = dylib.entry();
        let tls = dylib.tls();
        let tls_mod_id = tls.mod_id().map(|id| id.get());
        let tls_tp_offset = tls.tp_offset().map(|offset| offset.get());

        let dynamic_table = (!dynamic_ptr.is_null())
            .then(|| unsafe { copy_dynamic_table(dynamic_ptr) }.into_boxed_slice());
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
        user_data.needed_libs = needed_libs;
        user_data.dynamic_table = dynamic_table;
        user_data.link_map = Some(link_map);
        user_data.c_name = Some(c_name);
        #[cfg(feature = "std")]
        if let Some((start, end)) = mapped_range {
            crate::registry::register_module_state(start..end, &user_data.state);
        }
        Ok(())
    }
}

impl RelocationObserver for DlopenObserver {
    fn on_dynamic_relocated<D: 'static, R: RegionAccess, Tls: TlsResolver<NativeArch>>(
        &mut self,
        event: &mut DynamicRelocatedEvent<'_, D, NativeArch, R, Tls>,
    ) -> elf_loader::Result<()> {
        let fini = event
            .lifecycle_mut()
            .fini()
            .as_slice()
            .to_vec()
            .into_boxed_slice();
        let Some(data) = (event.core().user_data() as &dyn Any).downcast_ref::<ExtraData>() else {
            return Ok(());
        };
        data.fini.call_once(|| fini);
        let fini_ran = data.fini_ran.clone();
        let lifecycle = event.lifecycle_mut();
        lifecycle.set_fini_hook(move |event| {
            if fini_ran.load(Ordering::Acquire) {
                event.lifecycle_mut().clear();
            }
            Ok(())
        });
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

unsafe fn copy_dynamic_table(mut dynamic: *const ElfDyn) -> Vec<ElfDyn> {
    let mut table = Vec::new();
    while !dynamic.is_null() {
        let entry = unsafe { &*dynamic };
        table.push(ElfDyn::new(entry.tag(), entry.value()));
        if entry.tag() == elf_loader::elf::ElfDynamicTag::NULL {
            break;
        }
        dynamic = unsafe { dynamic.add(1) };
    }
    table
}
