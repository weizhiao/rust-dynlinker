use super::loader_lock::{Registry, RegistryGuard};
use crate::{
    ElfLibrary, OpenFlags,
    library::{ActiveTlsResolver, LoadedDylib, NativeElfModule, NativeModuleHandle},
};
use alloc::{borrow::ToOwned, sync::Arc, vec::Vec};
use elf_loader::{
    arch::NativeArch,
    image::Module,
    linker::{GraphModule, LinkContext, ModuleId, ModuleLease as NativeModuleLease, UnloadGroup},
    memory::VmAddr,
    runtime::DomainId,
};
use spin::Lazy;

pub(crate) type GlobalLinkContext = LinkContext<OpenFlags, NativeArch, ActiveTlsResolver>;
type GlobalUnloadGroup = UnloadGroup<OpenFlags, NativeArch, ActiveTlsResolver>;

pub(crate) struct ModuleLease {
    inner: Option<NativeModuleLease>,
}

impl ModuleLease {
    #[inline]
    const fn new(inner: NativeModuleLease) -> Self {
        Self { inner: Some(inner) }
    }
}

impl Drop for ModuleLease {
    fn drop(&mut self) {
        let Some(lease) = self.inner.take() else {
            return;
        };
        let unloaded = {
            let registry = REGISTRY.lock();
            registry.borrow_mut().release(lease)
        };
        drop(unloaded);
    }
}

pub(crate) struct LibrarySnapshot {
    inner: NativeModuleHandle,
    _lease: ModuleLease,
}

impl LibrarySnapshot {
    #[inline]
    const fn new(inner: NativeModuleHandle, lease: ModuleLease) -> Self {
        Self {
            inner,
            _lease: lease,
        }
    }

    #[inline]
    pub(crate) fn module(&self) -> &NativeElfModule {
        self.inner
            .downcast_ref()
            .expect("library snapshot must contain an ELF module")
    }
}

/// The process-wide dynamic-loader registry state.
pub(crate) struct Manager {
    link_ctx: GlobalLinkContext,
    adds: u64,
    subs: u64,
}

pub(crate) static REGISTRY: Lazy<Registry> = Lazy::new(|| {
    Registry::new(Manager {
        link_ctx: LinkContext::new(DomainId::PROCESS),
        adds: 0,
        subs: 0,
    })
});

/// Finds a symbol in the global search scope.
pub(crate) unsafe fn global_find<'a, T>(name: &str) -> Option<crate::Symbol<'a, T>> {
    let registry = REGISTRY.lock();
    registry.borrow().global_values().find_map(|lib| unsafe {
        lib.get::<T>(name).map(|sym| {
            log::trace!(
                "Lazy Binding: find symbol [{}] from [{}] in global scope ",
                name,
                lib.name()
            );
            core::mem::transmute(sym)
        })
    })
}

/// Finds the next occurrence of a symbol after the specified address.
pub(crate) unsafe fn next_find<'a, T>(addr: usize, name: &str) -> Option<crate::Symbol<'a, T>> {
    let registry = REGISTRY.lock();
    registry
        .borrow()
        .all_values()
        .skip_while(|lib| {
            lib.memory()
                .range_at(elf_loader::memory::VmAddr::new(addr))
                .is_none()
        })
        .skip(1)
        .find_map(|lib| unsafe {
            lib.get::<T>(name).map(|sym| {
                log::trace!(
                    "dlsym: find symbol [{}] from [{}] via RTLD_NEXT",
                    name,
                    lib.name()
                );
                core::mem::transmute(sym)
            })
        })
}

pub(crate) fn library_by_addr(addr: usize) -> Option<ElfLibrary> {
    log::trace!("library_by_addr: addr [{:#x}]", addr);
    REGISTRY.lock().borrow_mut().library_by_addr(addr)
}

pub(crate) fn loaded_by_addr(addr: usize) -> Option<NativeModuleHandle> {
    log::trace!("loaded_by_addr: addr [{:#x}]", addr);
    let registry = REGISTRY.lock();
    registry.borrow().module_by_addr(addr)
}

fn normalized_flags(name: &str, mut flags: OpenFlags) -> OpenFlags {
    if name.contains("libc")
        || name.contains("libpthread")
        || name.contains("libdl")
        || name.contains("libgcc_s")
        || name.contains("ld-linux")
        || name.contains("ld-musl")
    {
        flags |= OpenFlags::RTLD_NODELETE;
    }
    flags
}

fn libc_compat_aliases(name: &str) -> &'static [&'static str] {
    match name {
        "libc.so.6" => &[
            "libdl.so.2",
            "libpthread.so.0",
            "libutil.so.1",
            "librt.so.1",
            "libanl.so.1",
        ],
        "ld-linux-x86-64.so.2" => &["ld-linux.so.2"],
        _ => &[],
    }
}

impl Manager {
    #[inline]
    pub(crate) fn context_mut(&mut self) -> &mut GlobalLinkContext {
        &mut self.link_ctx
    }

    fn dylib(&self, id: ModuleId) -> Option<&NativeElfModule> {
        self.link_ctx.module(id).ok()?.downcast_ref()
    }

    fn committed_id(&self, key: &str) -> Option<ModuleId> {
        self.link_ctx.module_id(key)
    }

    /// Registers an object that was loaded before this linker took control.
    pub(crate) fn register_loaded(&mut self, lib: LoadedDylib, flags: OpenFlags) {
        assert!(
            lib.scope().is_empty() && lib.scope().lazy_scope().is_empty(),
            "preloaded module must not retain a relocation scope"
        );
        let handle = NativeModuleHandle::from(&*lib);
        let lib = handle
            .downcast_ref::<NativeElfModule>()
            .expect("preloaded handle must contain an ELF module");
        let name = lib.soname().unwrap_or_else(|| lib.name()).to_owned();
        let flags = normalized_flags(lib.name(), flags);
        let deps = lib
            .needed_libs()
            .iter()
            .filter_map(|needed| self.committed_id(needed))
            .filter_map(|id| self.link_ctx.module(id).ok())
            .map(|module| module.state().instance_id())
            .collect::<Vec<_>>();
        let lease = self
            .link_ctx
            .insert(GraphModule::with_meta(name.clone(), handle.clone(), flags).dependencies(deps))
            .expect("registry insert must not insert duplicate modules");
        let id = lease.id();
        self.adds += 1;

        self.add_alias(id, lib.path().file_name());
        if flags.is_global() || name.is_empty() {
            self.link_ctx
                .promote_global(id)
                .expect("registered global module must remain committed");
        }
        self.link_ctx
            .pin(lease)
            .expect("preloaded modules must remain committed");
    }

    pub(crate) fn add_alias(&mut self, id: ModuleId, alias: &str) {
        let key = self
            .link_ctx
            .module_key(id)
            .expect("alias target must already be committed");
        if alias.is_empty() || alias == key.as_str() {
            return;
        }
        self.link_ctx
            .add_alias(id, alias.to_owned())
            .expect("alias target must remain committed");
    }

    pub(crate) fn flags(&self, name: &str) -> Option<OpenFlags> {
        self.committed_id(name)
            .and_then(|id| self.link_ctx.meta(id).ok())
            .copied()
    }

    #[inline]
    pub(crate) fn all_values(
        &self,
    ) -> impl Iterator<Item = &(dyn Module<NativeArch, ActiveTlsResolver> + 'static)> + '_ {
        self.link_ctx
            .load_order()
            .filter_map(|id| self.link_ctx.module(id).ok())
    }

    pub(crate) fn global_values(&self) -> alloc::vec::IntoIter<NativeModuleHandle> {
        self.link_ctx
            .global_scope()
            .modules()
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .into_iter()
    }

    #[inline]
    pub(crate) fn main_library(&mut self) -> Option<ElfLibrary> {
        let id = self.link_ctx.load_order().next()?;
        self.open_module(id)
    }

    pub(crate) fn open_existing(&mut self, name: &str, flags: OpenFlags) -> Option<ElfLibrary> {
        let id = self.committed_id(name)?;
        self.promote(id, flags);
        self.open_module(id)
    }

    pub(crate) fn library_by_addr(&mut self, addr: usize) -> Option<ElfLibrary> {
        let id = self.module_id_by_addr(VmAddr::new(addr))?;
        self.open_module(id)
    }

    fn module_by_addr(&self, addr: usize) -> Option<NativeModuleHandle> {
        let id = self.module_id_by_addr(VmAddr::new(addr))?;
        let group = self.link_ctx.load_group(id).ok()?;
        let module = group.scope().first()?.clone();
        module.downcast_ref::<NativeElfModule>()?;
        Some(module)
    }

    fn module_id_by_addr(&self, addr: VmAddr) -> Option<ModuleId> {
        self.link_ctx.load_order().find(|id| {
            self.link_ctx
                .module(*id)
                .is_ok_and(|module| module.memory().range_at(addr).is_some())
        })
    }

    pub(crate) fn library_snapshot(&mut self) -> Vec<LibrarySnapshot> {
        let modules = self.link_ctx.load_order().collect::<Vec<_>>();
        modules
            .into_iter()
            .filter_map(|id| {
                let group = self.link_ctx.load_group(id).ok()?;
                let inner = group.scope().first()?.clone();
                inner.downcast_ref::<NativeElfModule>()?;
                let lease = self.acquire_module(id)?;
                Some(LibrarySnapshot::new(inner, lease))
            })
            .collect()
    }

    pub(crate) fn open_module(&mut self, id: ModuleId) -> Option<ElfLibrary> {
        let group = self.link_ctx.load_group(id).ok()?;
        let scope = group.scope().to_vec();
        scope.first()?.downcast_ref::<NativeElfModule>()?;
        let lease = self.acquire_module(id)?;
        Some(ElfLibrary::new(Arc::from(scope), lease))
    }

    pub(crate) fn acquire_module(&mut self, id: ModuleId) -> Option<ModuleLease> {
        self.link_ctx.acquire(id).ok().map(ModuleLease::new)
    }

    #[cfg(feature = "std")]
    pub(crate) fn acquire_module_by_addr(&mut self, addr: usize) -> Option<ModuleLease> {
        let id = self.module_id_by_addr(VmAddr::new(addr))?;
        self.acquire_module(id)
    }

    pub(crate) fn adds(&self) -> u64 {
        self.adds
    }

    pub(crate) fn subs(&self) -> u64 {
        self.subs
    }

    pub(crate) fn prepare_init(&mut self, root: ModuleId, flags: OpenFlags) {
        if flags.is_global() {
            self.link_ctx
                .promote_global(root)
                .expect("published root must remain committed");
        }
    }

    pub(crate) fn commit_published(&mut self, modules: &[ModuleId], flags: OpenFlags) {
        for &id in modules {
            let Some(lib) = self.dylib(id) else {
                continue;
            };
            let name = lib.name().to_owned();
            self.adds += 1;
            let module_flags = normalized_flags(&name, flags);
            *self
                .link_ctx
                .meta_mut(id)
                .expect("published module must have metadata") = module_flags;

            if module_flags.is_nodelete() {
                let lease = self
                    .link_ctx
                    .acquire(id)
                    .expect("published module must remain committed");
                self.link_ctx
                    .pin(lease)
                    .expect("published module must remain committed while pinning");
            }
        }
    }

    pub(crate) fn register_initial_aliases(&mut self) {
        for name in ["libc.so.6", "ld-linux-x86-64.so.2"] {
            let Some(id) = self.committed_id(name) else {
                continue;
            };
            for alias in libc_compat_aliases(name) {
                self.add_alias(id, alias);
            }
        }
    }

    pub(crate) fn promote(&mut self, id: ModuleId, flags: OpenFlags) {
        let flags = flags.promotable();
        let pin = {
            let meta = self
                .link_ctx
                .meta_mut(id)
                .expect("promoted module must remain committed");
            let pin = flags.is_nodelete() && !meta.is_nodelete();
            *meta |= flags;
            pin
        };
        if flags.is_global() {
            self.link_ctx
                .promote_global(id)
                .expect("promoted module must remain committed");
        }
        if pin {
            let lease = self
                .link_ctx
                .acquire(id)
                .expect("promoted module must remain committed");
            self.link_ctx
                .pin(lease)
                .expect("promoted module must remain committed while pinning");
        }
    }

    fn release(&mut self, lease: NativeModuleLease) -> GlobalUnloadGroup {
        let unloaded = self
            .link_ctx
            .release(lease)
            .expect("released module lease must belong to the global context");
        self.subs += unloaded.len() as u64;
        unloaded
    }
}

impl RegistryGuard<'_> {
    pub(crate) fn release_load(&self, load: elf_loader::linker::LoadResult) -> GlobalUnloadGroup {
        let mut manager = self.borrow_mut();
        let unloaded = load
            .release(manager.context_mut())
            .expect("load result must belong to the global context");
        manager.subs += unloaded.len() as u64;
        unloaded
    }
}
