use super::{
    GlobalMeta, LibraryLookup, Manager, PendingDylib, libc_compat_aliases, normalized_flags,
};
use crate::core_impl::loader::shortname_from_name;
use crate::{
    ElfLibrary, OpenFlags,
    core_impl::{DylibExt, ExtraData, FileIdentity, LoadedDylib},
};
use alloc::{
    borrow::{Cow, ToOwned},
    boxed::Box,
    collections::btree_set::BTreeSet,
    string::String,
    sync::Arc,
    vec,
    vec::Vec,
};
use elf_loader::image::{ModuleHandle, ModuleScope};
use elf_loader::linker::{LinkContext, ModuleId};

impl Manager {
    fn loaded_by_module(&self, id: ModuleId) -> Option<LoadedDylib> {
        self.link_ctx
            .get(id)
            .and_then(|module| module.downcast_ref::<LoadedDylib>().cloned())
    }

    fn committed_module(&self, key: &str) -> Option<ModuleId> {
        let id = self.link_ctx.key_id(key)?;
        self.link_ctx.module_id(id)
    }

    fn contains_canonical_key(&self, key: &str) -> bool {
        self.pending.contains_key(key) || self.committed_module(key).is_some()
    }

    fn committed_lookup<'a>(&'a self, key: &str) -> Option<LibraryLookup<'a>> {
        let id = self.committed_module(key)?;
        let inner = self.link_ctx.get(id)?;
        let shortname = self
            .link_ctx
            .module_key(id)
            .expect("committed module must resolve to an entry key");
        Some(LibraryLookup::Relocated {
            shortname: Cow::Borrowed(shortname),
            name: Cow::Borrowed(inner.name()),
        })
    }

    fn pending_lookup<'a>(&'a self, key: &str) -> Option<LibraryLookup<'a>> {
        self.pending
            .get_key_value(key)
            .map(|(shortname, _)| LibraryLookup::Pending {
                shortname: Cow::Borrowed(shortname),
            })
    }

    fn pending_alias_canonical<'a>(&'a self, alias: &str) -> Option<&'a str> {
        self.pending.iter().find_map(|(shortname, lib)| {
            lib.libnames
                .iter()
                .any(|name| name == alias)
                .then_some(shortname.as_str())
        })
    }

    fn canonical_name_owned(&self, name: &str) -> Option<String> {
        Some(self.lookup(name)?.shortname().to_owned())
    }

    fn promoted_name(&mut self, name: &str, flags: OpenFlags) -> Option<String> {
        let canonical = self.canonical_name_owned(name)?;
        self.promote(&canonical, flags);
        Some(canonical)
    }

    pub(crate) fn add_global(&mut self, id: ModuleId) {
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

    pub(super) fn add_loaded(
        &mut self,
        name: String,
        lib: LoadedDylib,
        flags: OpenFlags,
    ) -> ModuleId {
        debug_assert!(
            !self.contains_canonical_key(&name),
            "Library [{}] is already registered",
            name
        );
        let direct_deps = self.canonical_direct_deps(&lib);
        let id = self
            .link_ctx
            .insert_with_meta(
                name.clone(),
                lib,
                direct_deps,
                GlobalMeta {
                    flags,
                    libnames: Vec::new(),
                },
            )
            .expect("registry insert must not insert duplicate keys");
        self.adds += 1;
        log::trace!("Registered [{}] in global manager", name);
        id
    }

    pub(super) fn add_pending_reservation(&mut self, name: String, flags: OpenFlags) {
        debug_assert!(
            !self.contains_canonical_key(&name),
            "Library [{}] is already registered",
            name
        );
        let previous = self
            .pending
            .insert(name.clone(), PendingDylib::reserved(flags));
        debug_assert!(previous.is_none(), "Library [{}] is already pending", name);
        self.adds += 1;
        log::trace!("Reserved pending library [{}] in global manager", name);
    }

    pub(crate) fn add_alias(&mut self, canonical: &str, alias: &str) {
        debug_assert!(
            self.contains_canonical_key(canonical),
            "Canonical library [{}] must be registered before adding aliases",
            canonical
        );

        if alias.is_empty() || alias == canonical {
            return;
        }

        if self.contains_canonical_key(alias) {
            log::trace!(
                "Skipping alias [{}] for [{}]: the name is already used as a canonical key",
                alias,
                canonical
            );
            return;
        }

        if let Some(existing) = self.pending_alias_canonical(alias) {
            if existing != canonical {
                log::trace!(
                    "Skipping alias [{}] for [{}]: it already resolves to [{}]",
                    alias,
                    canonical,
                    existing
                );
            }
            return;
        }

        log::trace!("Adding alias [{}] to library [{}]", alias, canonical);
        if let Some(lib) = self.pending.get_mut(canonical) {
            lib.libnames.push(alias.to_owned());
        } else {
            let canonical = canonical.to_owned();
            let id = self
                .link_ctx
                .add_alias(&canonical, alias.to_owned())
                .expect("library alias must not target a different committed module");
            self.link_ctx
                .meta_mut(id)
                .expect("Canonical library must be registered before adding aliases")
                .libnames
                .push(alias.to_owned());
        }
    }

    pub(super) fn add_loaded_aliases(&mut self, canonical: &str, lib: &LoadedDylib) {
        self.add_alias(canonical, lib.shortname());
        self.add_alias(canonical, lib.path().file_name());
    }

    pub(crate) fn add_identity(&mut self, identity: FileIdentity, name: &str) {
        // Newest wins; identical inode implies same physical file.
        self.identities.insert(identity, name.to_owned());
    }

    pub(crate) fn remove(&mut self, shortname: &str) {
        let removed = if let Some(lib) = self.pending.shift_remove(shortname) {
            Some((None, lib.flags))
        } else if let Some(id) = self.committed_module(shortname) {
            self.link_ctx
                .remove(id)
                .map(|(_, _, meta)| (Some(id), meta.flags))
        } else {
            None
        };
        let Some((module_id, flags)) = removed else {
            panic!("Library is not registered");
        };
        self.subs += 1;
        let was_global = module_id.is_some_and(|id| self.global.shift_remove(&id));
        debug_assert!(
            module_id.is_none() || flags.is_global() == was_global,
            "Inconsistent global scope state when removing [{}]",
            shortname
        );
        // Remove any identity aliases pointing to this shortname.
        self.identities.retain(|_, v| v != shortname);
    }

    #[inline]
    pub(crate) fn lookup<'a>(&'a self, name: &str) -> Option<LibraryLookup<'a>> {
        // Primary lookup by canonical shortname.
        if let Some(lib) = self.committed_lookup(name) {
            return Some(lib);
        }
        if let Some(lib) = self.pending_lookup(name) {
            return Some(lib);
        }
        let canonical = self.pending_alias_canonical(name)?;
        self.pending_lookup(canonical)
    }

    pub(crate) fn flags(&self, name: &str) -> Option<OpenFlags> {
        if let Some(meta) = self
            .committed_module(name)
            .and_then(|id| self.link_ctx.meta(id))
        {
            return Some(meta.flags);
        }
        if let Some(lib) = self.pending.get(name) {
            return Some(lib.flags);
        }
        let canonical = self.pending_alias_canonical(name)?;
        self.pending.get(canonical).map(|lib| lib.flags)
    }

    #[inline]
    pub(crate) fn all_values(&self) -> impl Iterator<Item = LoadedDylib> + '_ {
        self.link_ctx
            .load_order()
            .filter_map(|id| self.loaded_by_module(id))
    }

    #[inline]
    pub(crate) fn global_values(&self) -> impl Iterator<Item = LoadedDylib> + '_ {
        self.global
            .iter()
            .filter_map(|id| self.loaded_by_module(*id))
    }

    pub(crate) fn adds(&self) -> u64 {
        self.adds
    }

    pub(crate) fn subs(&self) -> u64 {
        self.subs
    }

    #[inline]
    pub(crate) fn lookup_by_identity<'a>(
        &'a self,
        identity: &FileIdentity,
    ) -> Option<LibraryLookup<'a>> {
        self.identities
            .get(identity)
            .and_then(|name| self.lookup(name))
    }

    #[inline]
    pub(crate) fn main_library(&self) -> Option<ElfLibrary> {
        let id = self.link_ctx.load_order().next()?;
        let lib = self.loaded_by_module(id)?;
        let deps = self.library_scope_by_module(id)?;
        Some(ElfLibrary { inner: lib, deps })
    }

    pub(crate) fn canonical_direct_deps(&self, lib: &LoadedDylib) -> Box<[String]> {
        let mut deps = Vec::with_capacity(lib.needed_libs().len());
        let mut seen = BTreeSet::new();

        for needed in lib.needed_libs() {
            let shortname = self
                .lookup(needed)
                .map(|dep| dep.shortname().to_owned())
                .unwrap_or_else(|| needed.clone());
            if seen.insert(shortname.clone()) {
                deps.push(shortname);
            }
        }

        deps.into_boxed_slice()
    }

    pub(crate) fn relocation_scope(
        &self,
        group_scope: &ModuleScope,
        flags: OpenFlags,
    ) -> ModuleScope {
        let mut seen = BTreeSet::new();
        let mut scope = Vec::with_capacity(group_scope.len() + self.global.len());
        let mut push_unique = |module: ModuleHandle| {
            let shortname = module
                .downcast_ref::<LoadedDylib>()
                .map(DylibExt::shortname)
                .unwrap_or_else(|| shortname_from_name(module.name()));
            if seen.insert(shortname.to_owned()) {
                scope.push(module);
            }
        };

        if flags.is_deepbind() {
            for module in group_scope.iter().cloned() {
                push_unique(module);
            }
            for lib in self.global_values() {
                push_unique(lib.into());
            }
        } else {
            for lib in self.global_values() {
                push_unique(lib.into());
            }
            for module in group_scope.iter().cloned() {
                push_unique(module);
            }
        }

        ModuleScope::from(scope)
    }

    pub(crate) fn merge_link_context(
        &mut self,
        source: &LinkContext<String, ExtraData, GlobalMeta>,
        committed: impl IntoIterator<Item = ModuleId>,
        flags: OpenFlags,
    ) {
        for id in committed {
            let key = source
                .module_key(id)
                .expect("committed module must resolve to an entry key")
                .clone();
            if self.link_ctx.contains_key(&key) {
                continue;
            }

            let Some(module) = source.get(id).cloned() else {
                continue;
            };
            let loaded = module.downcast_ref::<LoadedDylib>().cloned();
            let direct_deps = source
                .direct_deps(id)
                .unwrap_or(&[])
                .iter()
                .map(|dep| {
                    source
                        .key(*dep)
                        .expect("direct dependency id must resolve in source link context")
                        .clone()
                })
                .collect::<Vec<_>>()
                .into_boxed_slice();
            let pending = self.pending.shift_remove(&key);
            let was_pending = pending.is_some();
            let meta = pending
                .map(|lib| GlobalMeta {
                    flags: lib.flags,
                    libnames: lib.libnames,
                })
                .unwrap_or_else(|| GlobalMeta {
                    flags: normalized_flags(
                        loaded
                            .as_ref()
                            .map(|lib| lib.name())
                            .unwrap_or_else(|| module.name()),
                        flags,
                    ),
                    libnames: Vec::new(),
                });
            let module_id = self
                .link_ctx
                .insert_with_meta(key.clone(), module.clone(), direct_deps, meta.clone())
                .expect("load merge must not insert duplicate keys");
            for alias in &meta.libnames {
                self.link_ctx
                    .add_alias(&key, alias.clone())
                    .expect("library alias must not target a different committed module");
            }
            if !was_pending {
                self.adds += 1;
            }
            if let Some(identity) = loaded
                .as_ref()
                .and_then(|lib| lib.user_data().file_identity)
            {
                self.add_identity(identity, &key);
            }
            if let Some(lib) = loaded.as_ref() {
                self.add_loaded_aliases(&key, lib);
            }
            for alias in libc_compat_aliases(&key) {
                self.add_alias(&key, alias);
            }
            if meta.flags.is_global() {
                self.add_global(module_id);
            }
        }
        debug_assert!(
            source.load_order().all(|id| source
                .module_key(id)
                .is_some_and(|key| self.link_ctx.contains_key(key))),
            "all source modules must be present in the global link context"
        );
    }

    pub(crate) fn visible_contains(&self, name: &str) -> bool {
        self.canonical_name_owned(name)
            .is_some_and(|canonical| self.link_ctx.contains_key(&canonical))
    }

    pub(crate) fn visible_direct_deps(&self, name: &str) -> Option<Box<[String]>> {
        let canonical = self.canonical_name_owned(name)?;
        if let Some(id) = self.committed_module(&canonical) {
            let direct_deps = self
                .link_ctx
                .direct_deps(id)?
                .iter()
                .map(|dep| {
                    self.link_ctx
                        .key(*dep)
                        .expect("direct dependency id must resolve in global link context")
                        .clone()
                })
                .collect::<Vec<_>>()
                .into_boxed_slice();
            return Some(direct_deps);
        }

        let lib = self.pending.get(&canonical)?;
        Some(self.canonical_direct_deps(lib.dylib_ref()?))
    }

    pub(crate) fn visible_loaded(&self, name: &str) -> Option<LoadedDylib> {
        let canonical = self.canonical_name_owned(name)?;
        self.committed_module(&canonical)
            .and_then(|id| self.loaded_by_module(id))
            .or_else(|| self.pending.get(&canonical).and_then(PendingDylib::dylib))
    }

    pub(crate) fn open_existing(&mut self, name: &str, flags: OpenFlags) -> Option<ElfLibrary> {
        let canonical = self.promoted_name(name, flags)?;
        self.get_lib(&canonical)
    }

    pub(crate) fn get_lib(&mut self, name: &str) -> Option<ElfLibrary> {
        let canonical = self.canonical_name_owned(name)?;
        let id = self.committed_module(&canonical)?;
        let deps = self.library_scope_by_module(id)?;
        let inner = self.loaded_by_module(id)?;
        Some(ElfLibrary { inner, deps })
    }

    pub(crate) fn promote(&mut self, shortname: &str, flags: OpenFlags) {
        let key = shortname.to_owned();
        let id = self
            .committed_module(&key)
            .expect("Library must be registered");
        let promotable = flags.promotable();
        let add_global = {
            let entry = self
                .link_ctx
                .meta_mut(id)
                .expect("Library must be registered");
            if entry.flags.contains(promotable) {
                false
            } else {
                entry.flags |= promotable;
                flags.is_global()
            }
        };
        if add_global {
            self.add_global(id);
        }
    }

    pub(crate) fn library_scope(&self, name: &str) -> Option<Arc<[LoadedDylib]>> {
        let canonical = self.canonical_name_owned(name)?;
        let id = self.committed_module(&canonical)?;
        self.library_scope_by_module(id)
    }

    pub(crate) fn library_scope_by_module(&self, id: ModuleId) -> Option<Arc<[LoadedDylib]>> {
        let deps = self
            .link_ctx
            .dependency_scope(id)
            .ok()?
            .into_iter()
            .filter_map(|id| self.loaded_by_module(id))
            .collect::<Vec<_>>();
        if !deps.is_empty() {
            return Some(Arc::from(deps));
        }

        self.loaded_by_module(id)
            .map(|entry| Arc::from(vec![entry]))
    }
}
