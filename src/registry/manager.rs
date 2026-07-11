use super::FileIdentity;
use super::{
    GlobalMeta, LibraryLookup, Manager, PendingDylib, PendingModuleId, libc_compat_aliases,
    normalized_flags,
};
use crate::{
    OpenFlags,
    image::{ActiveTlsResolver, DylibExt, ExtraData, LoadedDylib},
};
use alloc::{
    borrow::{Cow, ToOwned},
    boxed::Box,
    collections::btree_set::BTreeSet,
    string::String,
    vec::Vec,
};
use elf_loader::arch::NativeArch;
use elf_loader::linker::{LinkContext, ModuleId};

impl Manager {
    pub(super) fn loaded_by_module(&self, id: ModuleId) -> Option<LoadedDylib> {
        self.link_ctx
            .get(id)
            .ok()
            .and_then(|module| module.downcast_ref::<LoadedDylib>().cloned())
    }

    pub(super) fn committed_module(&self, key: &str) -> Option<ModuleId> {
        let id = self.link_ctx.key_id(key)?;
        self.link_ctx.module_id(id).ok().flatten()
    }

    fn pending_id(&self, key: &str) -> Option<PendingModuleId> {
        self.pending_keys.get(key).copied()
    }

    fn contains_key(&self, key: &str) -> bool {
        self.pending_keys.contains_key(key) || self.committed_module(key).is_some()
    }

    fn committed_lookup<'a>(&'a self, key: &str) -> Option<LibraryLookup<'a>> {
        let id = self.committed_module(key)?;
        let shortname = self
            .link_ctx
            .module_key(id)
            .expect("committed module must resolve to an entry key");
        Some(LibraryLookup::relocated(Cow::Borrowed(shortname)))
    }

    fn pending_lookup<'a>(&'a self, key: &str) -> Option<LibraryLookup<'a>> {
        let id = self.pending_id(key)?;
        self.pending
            .get(&id)
            .map(|lib| LibraryLookup::pending(Cow::Borrowed(lib.shortname())))
    }

    fn add_pending_alias(&mut self, id: PendingModuleId, alias: &str) {
        let lib = self
            .pending
            .get_mut(&id)
            .expect("pending alias target must be pending");
        lib.libnames.push(alias.to_owned());
        let previous = self.pending_keys.insert(alias.to_owned(), id);
        debug_assert!(previous.is_none(), "pending alias inserted twice");
    }

    fn remove_pending(&mut self, id: PendingModuleId) -> Option<PendingDylib> {
        let lib = self.pending.shift_remove(&id)?;
        let previous = self.pending_keys.remove(lib.shortname());
        debug_assert_eq!(
            previous,
            Some(id),
            "pending canonical name must point to the removed module"
        );
        for alias in &lib.libnames {
            let previous = self.pending_keys.remove(alias);
            debug_assert_eq!(
                previous,
                Some(id),
                "pending alias must point to the removed module"
            );
        }
        Some(lib)
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
            !self.contains_key(&name),
            "Library [{}] is already registered",
            name
        );
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
                    libnames: Vec::new(),
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

    pub(super) fn add_pending_reservation(
        &mut self,
        name: String,
        identity: Option<FileIdentity>,
        flags: OpenFlags,
    ) {
        debug_assert!(
            !self.contains_key(&name),
            "Library [{}] is already registered",
            name
        );
        let id = PendingModuleId::new(self.pending_next_id);
        self.pending_next_id = self
            .pending_next_id
            .checked_add(1)
            .expect("pending module id overflow");
        let previous = self.pending_keys.insert(name.clone(), id);
        debug_assert!(previous.is_none(), "Library [{}] is already pending", name);
        let pending = PendingDylib::reserved(name.clone(), identity, flags);
        if let Some(identity) = identity {
            self.identities.insert(identity, name);
        }
        self.adds += 1;
        log::trace!(
            "Reserved pending library [{}] in global manager",
            pending.shortname()
        );
        let previous = self.pending.insert(id, pending);
        debug_assert!(previous.is_none(), "pending module id inserted twice");
    }

    pub(crate) fn add_alias(&mut self, target: &str, alias: &str) {
        let pending_id = self.pending_id(target);

        if alias.is_empty() || alias == target {
            return;
        }

        if self.contains_key(alias) {
            log::trace!(
                "Skipping alias [{}] for [{}]: the name is already used",
                alias,
                target
            );
            return;
        }

        log::trace!("Adding alias [{}] to library [{}]", alias, target);
        if let Some(id) = pending_id {
            self.add_pending_alias(id, alias);
        } else {
            let id = self
                .committed_module(target)
                .expect("Alias target library must be registered before adding aliases");
            self.link_ctx
                .add_alias(id, alias.to_owned())
                .expect("library alias must not target a different committed module");
            self.link_ctx
                .meta_mut(id)
                .expect("Alias target library must be registered before adding aliases")
                .libnames
                .push(alias.to_owned());
        }
    }

    pub(crate) fn remove(&mut self, shortname: &str) {
        let removed = if let Some(id) = self.pending_id(shortname) {
            let lib = self
                .remove_pending(id)
                .expect("pending name must resolve to a pending module");
            Some((lib.identity, None, lib.flags))
        } else if let Some(id) = self.committed_module(shortname) {
            self.link_ctx
                .remove(id)
                .ok()
                .map(|(_, _, meta)| (meta.identity, Some(id), meta.flags))
        } else {
            None
        };
        let Some((identity, module_id, flags)) = removed else {
            panic!("Library is not registered");
        };
        self.subs += 1;
        let was_global = module_id.is_some_and(|id| self.global.shift_remove(&id));
        debug_assert!(
            module_id.is_none() || flags.is_global() == was_global,
            "Inconsistent global scope state when removing [{}]",
            shortname
        );
        if let Some(identity) = identity {
            self.identities.remove(&identity);
        }
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
        None
    }

    pub(crate) fn flags(&self, name: &str) -> Option<OpenFlags> {
        if let Some(meta) = self
            .committed_module(name)
            .and_then(|id| self.link_ctx.meta(id).ok())
        {
            return Some(meta.flags);
        }
        if let Some(id) = self.pending_id(name) {
            let lib = self
                .pending
                .get(&id)
                .expect("pending name must resolve to a pending module");
            return Some(lib.flags);
        }
        None
    }

    #[inline]
    pub(crate) fn all_values(&self) -> impl Iterator<Item = LoadedDylib> + '_ {
        self.link_ctx
            .load_order()
            .filter_map(|id| self.loaded_by_module(id))
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

    pub(crate) fn resolved_direct_deps(&self, lib: &LoadedDylib) -> Box<[String]> {
        let mut deps = Vec::with_capacity(lib.needed_libs().len());
        let mut seen = BTreeSet::new();

        for needed in lib.needed_libs() {
            let name = self
                .lookup(needed)
                .map(|dep| dep.name().to_owned())
                .unwrap_or_else(|| needed.clone());
            if seen.insert(name.clone()) {
                deps.push(name);
            }
        }

        deps.into_boxed_slice()
    }

    pub(crate) fn merge_link_context(
        &mut self,
        source: &LinkContext<String, ExtraData, GlobalMeta, NativeArch, ActiveTlsResolver>,
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

            let Ok(module) = source.get(id).cloned() else {
                continue;
            };
            let loaded = module.downcast_ref::<LoadedDylib>().cloned();
            let direct_deps = source
                .direct_deps(id)
                .expect("committed module must resolve direct dependencies")
                .map(|(dep_key, _)| {
                    source
                        .key(dep_key)
                        .expect("direct dependency id must resolve in source link context")
                        .clone()
                })
                .collect::<Vec<_>>()
                .into_boxed_slice();
            let pending = self.pending_id(&key).and_then(|id| {
                self.pending
                    .get(&id)
                    .is_some_and(|lib| lib.shortname() == key)
                    .then(|| self.remove_pending(id))
                    .flatten()
            });
            let was_pending = pending.is_some();
            let identity = pending.as_ref().and_then(|lib| lib.identity);
            let meta = pending
                .map(|lib| GlobalMeta {
                    identity,
                    flags: lib.flags,
                    libnames: lib.libnames,
                })
                .unwrap_or_else(|| GlobalMeta {
                    identity,
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
                    .add_alias(module_id, alias.clone())
                    .expect("library alias must not target a different committed module");
            }
            if !was_pending {
                self.adds += 1;
            }
            if let Some(identity) = meta.identity {
                self.identities.insert(identity, key.clone());
            }
            if let Some(lib) = loaded.as_ref() {
                self.add_alias(&key, lib.name());
                self.add_alias(&key, lib.path().file_name());
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
                .is_ok_and(|key| self.link_ctx.contains_key(key))),
            "all source modules must be present in the global link context"
        );
    }

    pub(crate) fn promote(&mut self, shortname: &str, flags: OpenFlags) {
        let id = self
            .committed_module(shortname)
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
}
