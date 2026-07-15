use super::loader_lock::{IdentityIndex, Registry, RegistryGuard};
use crate::{
    ElfLibrary, OpenFlags,
    image::{
        ActiveTlsResolver, DylibExt, ExtraData, HandleLease, LibrarySnapshot, LoadedDylib,
        contains_addr,
    },
};
use alloc::{
    borrow::ToOwned, boxed::Box, collections::btree_set::BTreeSet, string::String, sync::Arc, vec,
    vec::Vec,
};
use core::sync::atomic::Ordering;
use elf_loader::{
    arch::NativeArch,
    linker::{LinkContext, ModuleId},
};
use hashbrown::DefaultHashBuilder;
use spin::Lazy;

type IndexSet<K> = indexmap::IndexSet<K, DefaultHashBuilder>;
pub(crate) type GlobalLinkContext =
    LinkContext<String, ExtraData, GlobalMeta, NativeArch, ActiveTlsResolver>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct FileIdentity {
    pub(crate) dev: u64,
    pub(crate) ino: u64,
}

#[derive(Clone)]
pub(crate) struct GlobalMeta {
    pub(crate) identity: Option<FileIdentity>,
    pub(crate) flags: OpenFlags,
    pub(crate) direct_open_count: usize,
    pub(crate) pinned: bool,
}

impl Default for GlobalMeta {
    #[inline]
    fn default() -> Self {
        Self {
            identity: None,
            flags: OpenFlags::empty(),
            direct_open_count: 0,
            pinned: false,
        }
    }
}

impl GlobalMeta {
    pub(crate) fn loading(name: &str, identity: Option<FileIdentity>, flags: OpenFlags) -> Self {
        Self {
            identity,
            flags: normalized_flags(name, flags),
            direct_open_count: 0,
            pinned: false,
        }
    }

    pub(crate) fn matches(&self, key: &str, name: &str, identity: Option<FileIdentity>) -> bool {
        key == name
            || libc_compat_aliases(key).contains(&name)
            || identity.is_some_and(|identity| self.identity == Some(identity))
    }
}

/// The global manager for all loaded dynamic libraries.
pub(crate) struct Manager {
    /// Libraries available in the global symbol scope (RTLD_GLOBAL).
    global: IndexSet<ModuleId>,
    /// Fully linked modules indexed by canonical key.
    link_ctx: GlobalLinkContext,
    /// The number of times a new object has been added to the link map.
    adds: u64,
    /// The number of times an object has been removed from the link map.
    subs: u64,
}

/// The process-wide dynamic-loader registry.
pub(crate) static REGISTRY: Lazy<Registry> = Lazy::new(|| {
    Registry::new(Manager {
        global: IndexSet::with_hasher(DefaultHashBuilder::default()),
        link_ctx: LinkContext::new(),
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
        .skip_while(|lib| !contains_addr(lib, addr))
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

pub(crate) fn loaded_by_addr(addr: usize) -> Option<LoadedDylib> {
    log::trace!("loaded_by_addr: addr [{:#x}]", addr);
    REGISTRY.lock().borrow().loaded_by_addr(addr)
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

pub(crate) fn libc_compat_aliases(name: &str) -> &'static [&'static str] {
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

    fn committed(&self, id: ModuleId) -> Option<LoadedDylib> {
        self.link_ctx
            .get(id)
            .ok()
            .and_then(|module| module.downcast_ref::<LoadedDylib>().cloned())
    }

    fn committed_id(&self, key: &str) -> Option<ModuleId> {
        let id = self.link_ctx.key_id(key)?;
        self.link_ctx.module_id(id).ok().flatten()
    }

    fn remove_committed(
        &mut self,
        id: ModuleId,
        identities: &mut IdentityIndex,
    ) -> Option<LoadedDylib> {
        let loaded = self.committed(id);
        let (_, _, meta) = self
            .link_ctx
            .remove(id)
            .expect("removed module must still be committed");

        self.subs += 1;
        let was_global = self.global.shift_remove(&id);
        debug_assert!(
            !was_global || meta.flags.is_global(),
            "Non-global module [{id:?}] was present in global scope",
        );
        if let Some(identity) = meta.identity {
            identities.remove(identity);
        }
        loaded
    }

    fn add_global(&mut self, id: ModuleId) {
        let name = self
            .link_ctx
            .module_key(id)
            .expect("Global library must be registered before entering global scope");
        debug_assert!(
            !self.global.contains(&id),
            "Library [{}] is already in global scope",
            name
        );
        log::trace!("Adding [{}] to global scope", name);
        self.global.insert(id);
    }

    fn add_loaded(
        &mut self,
        name: String,
        lib: LoadedDylib,
        flags: OpenFlags,
        pinned: bool,
    ) -> ModuleId {
        let direct_deps = self.resolved_direct_deps(&lib);
        let id = self
            .link_ctx
            .insert_with_meta(
                name,
                lib,
                direct_deps,
                GlobalMeta {
                    identity: None,
                    flags,
                    direct_open_count: 0,
                    pinned,
                },
            )
            .expect("registry insert must not insert duplicate keys");
        self.adds += 1;
        let name = self
            .link_ctx
            .module_key(id)
            .expect("registered module must resolve to an entry key");
        log::trace!("Registered [{}] in global manager", name);
        id
    }

    /// Registers an object that was loaded before this linker took control.
    pub(crate) fn register_loaded(&mut self, lib: LoadedDylib, flags: OpenFlags) {
        let name = lib.name().to_owned();
        let flags = normalized_flags(lib.name(), flags);

        log::debug!(
            "Registering loaded library: [{}] (full path: [{}]) flags: [{:?}]",
            name,
            lib.name(),
            flags
        );

        let id = self.add_loaded(name.clone(), lib.clone(), flags, true);
        self.add_alias(&name, lib.path().file_name());
        for alias in libc_compat_aliases(&name) {
            self.add_alias(&name, alias);
        }
        if flags.is_global() || name.is_empty() {
            self.add_global(id);
        }
    }

    pub(crate) fn add_alias(&mut self, target: &str, alias: &str) {
        if alias.is_empty() || alias == target {
            return;
        }

        log::trace!("Adding alias [{}] to library [{}]", alias, target);
        let id = self
            .committed_id(target)
            .expect("Alias target library must be registered before adding aliases");
        self.link_ctx
            .add_alias(id, alias.to_owned())
            .expect("library alias must not target a different committed module");
    }

    #[inline]
    pub(crate) fn lookup(&self, name: &str) -> Option<&str> {
        let id = self.committed_id(name)?;
        self.link_ctx.module_key(id).ok().map(String::as_str)
    }

    pub(crate) fn flags(&self, name: &str) -> Option<OpenFlags> {
        self.committed_id(name)
            .and_then(|id| self.link_ctx.meta(id).ok())
            .map(|meta| meta.flags)
    }

    #[inline]
    pub(crate) fn all_values(&self) -> impl Iterator<Item = LoadedDylib> + '_ {
        self.link_ctx
            .load_order()
            .filter_map(|id| self.committed(id))
    }

    #[inline]
    pub(crate) fn global_values(&self) -> impl Iterator<Item = LoadedDylib> + '_ {
        self.global.iter().filter_map(|id| self.committed(*id))
    }

    #[inline]
    pub(crate) fn main_library(&mut self) -> Option<ElfLibrary> {
        let id = self.link_ctx.load_order().next()?;
        self.open_module(id)
    }

    pub(crate) fn open_existing(&mut self, name: &str, flags: OpenFlags) -> Option<ElfLibrary> {
        self.promote(name, flags);
        self.get_lib(name)
    }

    fn get_lib(&mut self, name: &str) -> Option<ElfLibrary> {
        let id = self.committed_id(name)?;
        self.open_module(id)
    }

    pub(crate) fn library_by_addr(&mut self, addr: usize) -> Option<ElfLibrary> {
        let id = {
            self.link_ctx.load_order().find(|id| {
                self.committed(*id)
                    .is_some_and(|lib| contains_addr(&lib, addr))
            })
        }?;
        self.open_module(id)
    }

    pub(crate) fn loaded_by_addr(&self, addr: usize) -> Option<LoadedDylib> {
        self.all_values().find(|lib| contains_addr(lib, addr))
    }

    pub(crate) fn library_snapshot(&mut self) -> Vec<LibrarySnapshot> {
        let modules = self.link_ctx.load_order().collect::<Vec<_>>();
        modules
            .into_iter()
            .filter_map(|id| {
                let inner = self.committed(id)?;
                let lease = self.acquire_module(id)?;
                Some(LibrarySnapshot::new(inner, lease))
            })
            .collect()
    }

    pub(crate) fn open_module(&mut self, id: ModuleId) -> Option<ElfLibrary> {
        let deps = self.library_scope_by_module(id)?;
        let inner = self.committed(id)?;
        let lease = self.acquire_module(id)?;
        Some(ElfLibrary::new(inner, deps, lease))
    }

    fn library_scope_by_module(&self, id: ModuleId) -> Option<Arc<[LoadedDylib]>> {
        let deps = self
            .link_ctx
            .dependency_scope(id)
            .ok()?
            .into_iter()
            .filter_map(|id| self.committed(id))
            .collect::<Vec<_>>();
        if !deps.is_empty() {
            return Some(Arc::from(deps));
        }
        self.committed(id).map(|entry| Arc::from(vec![entry]))
    }

    pub(crate) fn adds(&self) -> u64 {
        self.adds
    }

    pub(crate) fn subs(&self) -> u64 {
        self.subs
    }

    fn resolved_direct_deps(&self, lib: &LoadedDylib) -> Box<[String]> {
        let mut deps = Vec::with_capacity(lib.needed_libs().len());
        let mut seen = BTreeSet::new();

        for needed in lib.needed_libs() {
            let name = self
                .lookup(needed)
                .map(ToOwned::to_owned)
                .unwrap_or_else(|| needed.clone());
            if seen.insert(name.clone()) {
                deps.push(name);
            }
        }

        deps.into_boxed_slice()
    }

    fn register_committed(&mut self, modules: &[ModuleId], identities: &mut IdentityIndex) {
        for &id in modules {
            self.adds += 1;
            if let Some(identity) = self
                .link_ctx
                .meta(id)
                .expect("committed module must have metadata")
                .identity
            {
                let key = self
                    .link_ctx
                    .module_key(id)
                    .expect("committed module must have a canonical key")
                    .clone();
                identities.insert(identity, key);
            }
        }
    }

    fn add_globals(&mut self, modules: &[ModuleId]) {
        for &id in modules {
            let should_add = self
                .link_ctx
                .meta(id)
                .is_ok_and(|meta| meta.flags.is_global())
                && !self.global.contains(&id);
            if should_add {
                self.add_global(id);
            }
        }
    }

    fn rollback_committed(
        &mut self,
        modules: &[ModuleId],
        identities: &mut IdentityIndex,
    ) -> Vec<LoadedDylib> {
        modules
            .iter()
            .rev()
            .filter_map(|&id| self.remove_committed(id, identities))
            .collect()
    }

    fn promote(&mut self, name: &str, flags: OpenFlags) {
        let id = self.committed_id(name).expect("Library must be registered");
        self.link_ctx
            .meta_mut(id)
            .expect("Library must be registered")
            .flags |= flags.promotable();
        if flags.is_global() && !self.global.contains(&id) {
            self.add_global(id);
        }
    }

    fn acquire_module(&mut self, id: ModuleId) -> Option<HandleLease> {
        let meta = self.link_ctx.meta_mut(id).ok()?;
        meta.direct_open_count = meta
            .direct_open_count
            .checked_add(1)
            .expect("direct dlopen count overflow");
        Some(HandleLease::new(id))
    }

    fn release_handle(&mut self, id: ModuleId, identities: &mut IdentityIndex) -> Vec<LoadedDylib> {
        let Ok(meta) = self.link_ctx.meta_mut(id) else {
            return Vec::new();
        };
        debug_assert!(
            meta.direct_open_count > 0,
            "released library handle must have a matching acquisition"
        );
        let Some(next_count) = meta.direct_open_count.checked_sub(1) else {
            return Vec::new();
        };
        meta.direct_open_count = next_count;
        if next_count != 0 {
            return Vec::new();
        }

        self.collect_unreachable(identities)
    }

    fn collect_unreachable(&mut self, identities: &mut IdentityIndex) -> Vec<LoadedDylib> {
        loop {
            let mut reachable = BTreeSet::new();
            let mut pending = self
                .link_ctx
                .load_order()
                .filter(|id| {
                    self.link_ctx.meta(*id).is_ok_and(|meta| {
                        meta.pinned || meta.flags.is_nodelete() || meta.direct_open_count != 0
                    }) || self
                        .committed(*id)
                        .is_some_and(|lib| lib.user_data().state.has_tls_dtors())
                })
                .collect::<Vec<_>>();

            while let Some(id) = pending.pop() {
                if !reachable.insert(id) {
                    continue;
                }
                if let Ok(deps) = self.link_ctx.direct_deps(id) {
                    pending.extend(deps.map(|(_, dep)| dep));
                }
            }

            let unreachable = self
                .link_ctx
                .load_order()
                .filter(|id| !reachable.contains(id))
                .collect::<Vec<_>>();
            let mut marked = Vec::with_capacity(unreachable.len());
            let mut retry = false;
            for id in &unreachable {
                if let Some(state) = self.committed(*id).map(|lib| lib.user_data().state.clone()) {
                    if !state.begin_unload() {
                        retry = true;
                        break;
                    }
                    marked.push(state);
                }
            }
            if retry {
                for state in marked {
                    state.cancel_unload();
                }
                continue;
            }

            return unreachable
                .into_iter()
                .filter_map(|id| self.remove_committed(id, identities))
                .collect();
        }
    }
}

impl RegistryGuard<'_> {
    pub(crate) fn register_committed(&self, modules: &[ModuleId]) {
        self.borrow_mut()
            .register_committed(modules, &mut self.identities_mut());
    }

    pub(crate) fn rollback_committed(&self, modules: &[ModuleId]) -> Vec<LoadedDylib> {
        self.borrow_mut()
            .rollback_committed(modules, &mut self.identities_mut())
    }

    pub(crate) fn publish(&self, modules: &[ModuleId]) {
        self.borrow_mut().add_globals(modules);
    }

    pub(crate) fn release_handle(&self, id: ModuleId) -> Vec<LoadedDylib> {
        self.borrow_mut()
            .release_handle(id, &mut self.identities_mut())
    }

    #[cfg(feature = "std")]
    pub(crate) fn collect_unreachable(&self) -> Vec<LoadedDylib> {
        self.borrow_mut()
            .collect_unreachable(&mut self.identities_mut())
    }
}

fn run_fini(lib: &LoadedDylib) {
    if !lib.is_init() {
        return;
    }
    let data = lib.user_data();
    let Some(fini) = data.fini.get() else {
        return;
    };
    if data.fini_ran.swap(true, Ordering::AcqRel) {
        return;
    }

    for addr in fini.iter().copied() {
        let fini: unsafe extern "C" fn() = unsafe { core::mem::transmute(addr.get()) };
        unsafe { fini() };
    }
}

pub(crate) fn destroy_libraries(libraries: Vec<LoadedDylib>) {
    let _registry = REGISTRY.lock();
    // Keep the whole group alive while lazy PLT entries used by fini resolve.
    for lib in &libraries {
        log::info!("Destroying dylib [{}]", lib.name());
        run_fini(lib);
    }
}

pub(crate) fn release_handle(module: ModuleId) {
    let registry = REGISTRY.lock();
    let libraries = registry.release_handle(module);
    destroy_libraries(libraries);
}
