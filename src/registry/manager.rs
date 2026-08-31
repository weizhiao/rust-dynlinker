use super::loader_lock::Registry;
#[cfg(not(feature = "std"))]
use crate::abi::link_map::LinkMap;
use crate::{
    ElfLibrary, OpenFlags,
    library::{ActiveTlsResolver, LoadedDylib, NativeElfModule, NativeModuleHandle, OpenedLibrary},
};
use alloc::{
    borrow::ToOwned,
    collections::{BTreeMap, btree_map::Entry},
    vec::Vec,
};
#[cfg(not(feature = "std"))]
use elf_loader::image::Module;
use elf_loader::{
    arch::NativeArch,
    linker::{
        GraphModule, LinkContext, LoadResult, ModuleId, ModuleLease as NativeModuleLease,
        UnloadGroup,
    },
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

    #[inline]
    pub(crate) fn id(&self) -> ModuleId {
        self.inner
            .as_ref()
            .expect("live module lease must retain its identity")
            .id()
    }

    #[inline]
    fn into_inner(mut self) -> NativeModuleLease {
        self.inner
            .take()
            .expect("live module lease must retain its acquisition")
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

struct HandleState {
    opened: OpenedLibrary,
    // Each additional C dlopen keeps its own Relink acquisition.
    extra_leases: Vec<ModuleLease>,
}

/// The process-wide dynamic-loader registry state.
pub(crate) struct Manager {
    link_ctx: GlobalLinkContext,
    handles: BTreeMap<usize, HandleState>,
    adds: u64,
    subs: u64,
}

pub(crate) static REGISTRY: Lazy<Registry> = Lazy::new(|| {
    Registry::new(Manager {
        link_ctx: LinkContext::new(DomainId::PROCESS),
        handles: BTreeMap::new(),
        adds: 0,
        subs: 0,
    })
});

/// Finds a symbol in the global search scope.
pub(crate) unsafe fn global_find<'a, T>(name: &str) -> Option<crate::Symbol<'a, T>> {
    let registry = REGISTRY.lock();
    let manager = registry.borrow();
    let global = manager.link_ctx.global_scope().modules();
    global.iter().find_map(|lib| unsafe {
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
    unsafe { registry.borrow_mut().next_find(addr, name) }
}

unsafe fn find_symbol<'symbol, 'module, T>(
    mut modules: impl Iterator<Item = &'module NativeModuleHandle>,
    name: &str,
) -> Option<crate::Symbol<'symbol, T>> {
    modules.find_map(|lib| unsafe {
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

impl Manager {
    unsafe fn next_find<'a, T>(&mut self, addr: usize, name: &str) -> Option<crate::Symbol<'a, T>> {
        let caller = self.link_ctx.module_id_at(VmAddr::new(addr))?;
        let caller_instance = self.link_ctx.module(caller).ok()?.state().instance_id();
        let global = self.link_ctx.global_scope().modules();
        let scope = if global
            .iter()
            .any(|module| module.state().instance_id() == caller_instance)
        {
            global
        } else {
            self.link_ctx.load_group(caller).ok()?
        };

        unsafe {
            find_symbol(
                scope
                    .iter()
                    .skip_while(|module| module.state().instance_id() != caller_instance)
                    .skip(1),
                name,
            )
        }
    }
}

pub(crate) fn register_handle(opened: OpenedLibrary) -> usize {
    let registry = REGISTRY.lock();
    registry.borrow_mut().register_handle(opened)
}

pub(crate) fn release_handle(handle: usize) -> bool {
    let unloaded = {
        let registry = REGISTRY.lock();
        registry.borrow_mut().release_handle(handle)
    };
    let valid = unloaded.is_some();
    drop(unloaded);
    valid
}

pub(crate) unsafe fn handle_find<'a, T>(handle: usize, name: &str) -> Option<crate::Symbol<'a, T>> {
    let registry = REGISTRY.lock();
    let manager = registry.borrow();
    manager
        .handles
        .get(&handle)?
        .opened
        .scope()
        .iter()
        .find_map(|module| unsafe {
            module
                .get::<T>(name)
                .map(|symbol| core::mem::transmute(symbol))
        })
}

#[cfg(not(feature = "std"))]
pub(crate) fn handle_link_map(handle: usize) -> Option<*mut LinkMap> {
    let registry = REGISTRY.lock();
    let manager = registry.borrow();
    manager
        .handles
        .contains_key(&handle)
        .then_some(handle as *mut LinkMap)
}

pub(crate) fn library_by_addr(addr: usize) -> Option<ElfLibrary> {
    log::trace!("library_by_addr: addr [{:#x}]", addr);
    REGISTRY
        .lock()
        .borrow_mut()
        .library_by_addr(addr)
        .map(ElfLibrary::from)
}

pub(crate) fn loaded_by_addr(addr: usize) -> Option<NativeModuleHandle> {
    log::trace!("loaded_by_addr: addr [{:#x}]", addr);
    let registry = REGISTRY.lock();
    registry.borrow_mut().module_by_addr(addr)
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

    fn register_handle(&mut self, opened: OpenedLibrary) -> usize {
        let handle = opened.link_map() as usize;
        match self.handles.entry(handle) {
            Entry::Vacant(entry) => {
                entry.insert(HandleState {
                    opened,
                    extra_leases: Vec::new(),
                });
            }
            Entry::Occupied(mut entry) => {
                entry.get_mut().extra_leases.push(opened.into_lease());
            }
        }
        handle
    }

    fn release_handle(&mut self, handle: usize) -> Option<GlobalUnloadGroup> {
        let lease = match self.handles.entry(handle) {
            Entry::Vacant(_) => return None,
            Entry::Occupied(mut entry) => match entry.get_mut().extra_leases.pop() {
                Some(lease) => lease,
                None => entry.remove().opened.into_lease(),
            },
        };
        Some(self.release(lease.into_inner()))
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
        let deps = lib
            .needed_libs()
            .iter()
            .filter_map(|needed| self.link_ctx.module_id(needed))
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

    pub(crate) fn flags(&self, id: ModuleId) -> Option<OpenFlags> {
        self.link_ctx.meta(id).ok().copied()
    }

    #[inline]
    #[cfg(not(feature = "std"))]
    pub(crate) fn all_values(
        &self,
    ) -> impl Iterator<Item = &(dyn Module<NativeArch, ActiveTlsResolver> + 'static)> + '_ {
        self.link_ctx
            .load_order()
            .filter_map(|id| self.link_ctx.module(id).ok())
    }

    #[inline]
    pub(crate) fn main_library(&mut self) -> Option<OpenedLibrary> {
        let id = self.link_ctx.load_order().next()?;
        self.open_module(id)
    }

    pub(crate) fn open_existing(&mut self, key: &str, flags: OpenFlags) -> Option<OpenedLibrary> {
        let id = self.link_ctx.module_id(key)?;
        self.promote(id, flags);
        self.open_module(id)
    }

    pub(crate) fn library_by_addr(&mut self, addr: usize) -> Option<OpenedLibrary> {
        let id = self.link_ctx.module_id_at(VmAddr::new(addr))?;
        self.open_module(id)
    }

    fn module_by_addr(&mut self, addr: usize) -> Option<NativeModuleHandle> {
        let id = self.link_ctx.module_id_at(VmAddr::new(addr))?;
        let scope = self.link_ctx.load_group(id).ok()?;
        let module = scope.first()?.clone();
        module.downcast_ref::<NativeElfModule>()?;
        Some(module)
    }

    pub(crate) fn library_snapshot(&mut self) -> Vec<LibrarySnapshot> {
        let modules = self.link_ctx.load_order().collect::<Vec<_>>();
        modules
            .into_iter()
            .filter_map(|id| {
                let scope = self.link_ctx.load_group(id).ok()?;
                let inner = scope.first()?.clone();
                inner.downcast_ref::<NativeElfModule>()?;
                let lease = self.acquire_module(id)?;
                Some(LibrarySnapshot::new(inner, lease))
            })
            .collect()
    }

    pub(crate) fn open_module(&mut self, id: ModuleId) -> Option<OpenedLibrary> {
        let scope = self.link_ctx.load_group(id).ok()?;
        let lease = self.acquire_module(id)?;
        Some(OpenedLibrary::new(scope, lease))
    }

    pub(crate) fn acquire_module(&mut self, id: ModuleId) -> Option<ModuleLease> {
        self.link_ctx.acquire(id).ok().map(ModuleLease::new)
    }

    #[cfg(feature = "std")]
    pub(crate) fn acquire_module_by_addr(&mut self, addr: usize) -> Option<ModuleLease> {
        let id = self.link_ctx.module_id_at(VmAddr::new(addr))?;
        self.acquire_module(id)
    }

    pub(crate) fn adds(&self) -> u64 {
        self.adds
    }

    pub(crate) fn subs(&self) -> u64 {
        self.subs
    }

    pub(crate) fn open_load(&mut self, load: LoadResult, flags: OpenFlags) -> OpenedLibrary {
        let (lease, modules) = load.into_parts();
        for &id in &modules {
            self.adds += 1;
            *self
                .link_ctx
                .meta_mut(id)
                .expect("published module must have metadata") = flags;

            if flags.is_nodelete() {
                let lease = self
                    .link_ctx
                    .acquire(id)
                    .expect("published module must remain committed");
                self.link_ctx
                    .pin(lease)
                    .expect("published module must remain committed while pinning");
            }
        }

        if flags.is_global() {
            self.link_ctx
                .promote_global(lease.id())
                .expect("loaded root module must remain committed");
        }

        let scope = self
            .link_ctx
            .load_group(lease.id())
            .expect("linked root module must be registered");
        OpenedLibrary::new(scope, ModuleLease::new(lease))
    }

    pub(crate) fn register_initial_aliases(&mut self) {
        for name in ["libc.so.6", "ld-linux-x86-64.so.2"] {
            let Some(id) = self.link_ctx.module_id(name) else {
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
