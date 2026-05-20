use super::{
    GlobalMeta, LibraryLookup, Manager, PendingDylib, libc_compat_aliases, loaded_from_module,
    normalized_flags,
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
use elf_loader::linker::{KeyId, LinkContext};

impl Manager {
    fn loaded_by_id(&self, id: KeyId) -> Option<LoadedDylib> {
        self.link_ctx.get(id).and_then(loaded_from_module)
    }

    fn committed_id(&self, key: &str) -> Option<KeyId> {
        let id = self.link_ctx.key_id(&key.to_owned())?;
        self.link_ctx.contains(id).then_some(id)
    }

    fn contains_canonical_key(&self, key: &str) -> bool {
        self.pending.contains_key(key) || self.committed_id(key).is_some()
    }

    fn committed_lookup<'a>(&'a self, key: &str) -> Option<LibraryLookup<'a>> {
        let key = key.to_owned();
        let id = self.committed_id(&key)?;
        let inner = self.link_ctx.get(id)?;
        Some(LibraryLookup::Relocated {
            shortname: Cow::Owned(key),
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

    fn canonical_name_owned(&self, name: &str) -> Option<String> {
        Some(self.lookup(name)?.shortname().to_owned())
    }

    fn promoted_name(&mut self, name: &str, flags: OpenFlags) -> Option<String> {
        let canonical = self.canonical_name_owned(name)?;
        self.promote(&canonical, flags);
        Some(canonical)
    }

    pub(crate) fn add_global(&mut self, name: String, lib: LoadedDylib) {
        debug_assert!(
            !self.global.contains_key(&name),
            "Library [{}] is already in global scope",
            name
        );
        log::trace!("Adding [{}] to global scope", name);
        self.global.insert(name, lib);
    }

    pub(super) fn add_loaded(&mut self, name: String, lib: LoadedDylib, flags: OpenFlags) {
        debug_assert!(
            !self.contains_canonical_key(&name),
            "Library [{}] is already registered",
            name
        );
        let direct_deps = self.canonical_direct_deps(&lib);
        self.link_ctx
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

        if let Some(existing) = self.aliases.get(alias) {
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
                .key_id(&canonical)
                .expect("Canonical library must be registered before adding aliases");
            self.link_ctx
                .meta_mut(id)
                .expect("Canonical library must be registered before adding aliases")
                .libnames
                .push(alias.to_owned());
        }
        self.aliases.insert(alias.to_owned(), canonical.to_owned());
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
            Some((false, lib.flags, lib.libnames))
        } else if let Some(id) = self.committed_id(shortname) {
            self.link_ctx
                .remove(id)
                .map(|(_, _, meta)| (true, meta.flags, meta.libnames))
        } else {
            None
        };
        let Some((was_committed, flags, libnames)) = removed else {
            panic!("Library is not registered");
        };
        self.subs += 1;
        let res = self.global.shift_remove(shortname);
        debug_assert!(
            !was_committed || flags.is_global() == res.is_some(),
            "Inconsistent global scope state when removing [{}]",
            shortname
        );
        for alias in &libnames {
            self.aliases.remove(alias);
        }
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
        let canonical = self.aliases.get(name)?;
        self.committed_lookup(canonical)
            .or_else(|| self.pending_lookup(canonical))
    }

    pub(crate) fn flags(&self, name: &str) -> Option<OpenFlags> {
        if let Some(meta) = self
            .committed_id(name)
            .and_then(|id| self.link_ctx.meta(id))
        {
            return Some(meta.flags);
        }
        if let Some(lib) = self.pending.get(name) {
            return Some(lib.flags);
        }
        let canonical = self.aliases.get(name)?;
        self.committed_id(canonical)
            .and_then(|id| self.link_ctx.meta(id))
            .map(|meta| meta.flags)
            .or_else(|| self.pending.get(canonical).map(|lib| lib.flags))
    }

    #[inline]
    pub(crate) fn all_values(&self) -> impl Iterator<Item = LoadedDylib> + '_ {
        self.link_ctx
            .load_order()
            .filter_map(|id| self.loaded_by_id(id))
    }

    #[inline]
    pub(crate) fn global_values(&self) -> indexmap::map::Values<'_, String, LoadedDylib> {
        self.global.values()
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
        let lib = self.loaded_by_id(id)?;
        let deps = self.library_scope_by_id(id)?;
        Some(ElfLibrary {
            inner: lib,
            deps: Some(deps),
        })
    }

    pub(crate) fn canonical_direct_deps(&self, lib: &LoadedDylib) -> Box<[String]> {
        let mut deps = Vec::with_capacity(lib.needed_libs().len());
        let mut seen = BTreeSet::new();

        for needed in lib.needed_libs() {
            let Some(dep) = self.lookup(needed) else {
                continue;
            };
            let shortname = dep.shortname().to_owned();
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
                .as_loaded::<ExtraData>()
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

    #[allow(unused)]
    pub(crate) fn rebuild_link_ctx(&mut self) {
        let entries = self
            .link_ctx
            .load_order()
            .map(|id| {
                let key = self
                    .link_ctx
                    .key(id)
                    .expect("load_order entries must resolve to interned keys");
                let module = self
                    .link_ctx
                    .get(id)
                    .cloned()
                    .expect("load_order entries must resolve to committed modules");
                let meta = self
                    .link_ctx
                    .meta(id)
                    .cloned()
                    .expect("load_order entries must resolve to committed metadata");
                let direct_deps = if let Some(lib) = module.as_loaded::<ExtraData>() {
                    self.canonical_direct_deps(lib)
                } else {
                    self.link_ctx
                        .direct_deps(id)
                        .unwrap_or(&[])
                        .iter()
                        .map(|dep| {
                            self.link_ctx
                                .key(*dep)
                                .expect("direct dependency id must resolve in global link context")
                                .clone()
                        })
                        .collect::<Vec<_>>()
                        .into_boxed_slice()
                };
                (key.clone(), module, direct_deps, meta)
            })
            .collect::<Vec<_>>();

        self.link_ctx = LinkContext::new();
        for (key, module, direct_deps, meta) in entries {
            self.link_ctx
                .insert_with_meta(key, module, direct_deps, meta)
                .expect("registry rebuild must not insert duplicate keys");
        }
    }

    pub(crate) fn merge_link_context(
        &mut self,
        source: &LinkContext<String, ExtraData, GlobalMeta>,
        committed: impl IntoIterator<Item = KeyId>,
        flags: OpenFlags,
    ) {
        for id in committed {
            let key = source
                .key(id)
                .expect("committed id must resolve in source link context")
                .clone();
            if self.link_ctx.contains_key(&key) {
                continue;
            }

            let Some(module) = source.get(id).cloned() else {
                continue;
            };
            let loaded = loaded_from_module(&module);
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
            self.link_ctx
                .insert_with_meta(key.clone(), module.clone(), direct_deps, meta.clone())
                .expect("load merge must not insert duplicate keys");
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
            if meta.flags.is_global()
                && let Some(lib) = loaded
            {
                self.add_global(key.clone(), lib);
            }
        }
        debug_assert!(
            source.load_order().all(|id| source
                .key(id)
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
        if let Some(id) = self.committed_id(&canonical) {
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
        self.committed_id(&canonical)
            .and_then(|id| self.loaded_by_id(id))
            .or_else(|| self.pending.get(&canonical).and_then(PendingDylib::dylib))
    }

    pub(crate) fn open_existing(&mut self, name: &str, flags: OpenFlags) -> Option<ElfLibrary> {
        let canonical = self.promoted_name(name, flags)?;
        self.get_lib(&canonical)
    }

    pub(crate) fn get_lib(&mut self, name: &str) -> Option<ElfLibrary> {
        let canonical = self.canonical_name_owned(name)?;
        let id = self.committed_id(&canonical)?;
        let deps = self.library_scope_by_id(id)?;
        let inner = self.loaded_by_id(id)?;
        Some(ElfLibrary {
            inner,
            deps: Some(deps),
        })
    }

    pub(crate) fn promote(&mut self, shortname: &str, flags: OpenFlags) {
        let key = shortname.to_owned();
        let id = self.committed_id(&key).expect("Library must be registered");
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
            let core = self
                .loaded_by_id(id)
                .expect("Promoted library must be loaded");
            self.add_global(key, core);
        }
    }

    pub(crate) fn library_scope(&self, name: &str) -> Option<Arc<[LoadedDylib]>> {
        let canonical = self.canonical_name_owned(name)?;
        let id = self.committed_id(&canonical)?;
        self.library_scope_by_id(id)
    }

    pub(crate) fn library_scope_by_id(&self, id: KeyId) -> Option<Arc<[LoadedDylib]>> {
        let deps = self
            .link_ctx
            .dependency_scope(id)
            .into_iter()
            .filter_map(|id| self.loaded_by_id(id))
            .collect::<Vec<_>>();
        if !deps.is_empty() {
            return Some(Arc::from(deps));
        }

        self.loaded_by_id(id).map(|entry| Arc::from(vec![entry]))
    }
}
