use super::Manager;
use crate::{
    ElfLibrary, OpenFlags,
    image::{ActiveTlsResolver, LoadedDylib},
};
use alloc::{
    borrow::ToOwned, boxed::Box, collections::btree_set::BTreeSet, string::String, sync::Arc, vec,
    vec::Vec,
};
use elf_loader::{
    arch::NativeArch,
    image::{ModuleHandle, ModuleScope, ModuleScopeBuilder},
    linker::ModuleId,
};

type DlopenModuleHandle = ModuleHandle<NativeArch, ActiveTlsResolver>;
type DlopenModuleScope = ModuleScope<NativeArch, ActiveTlsResolver>;
type DlopenModuleScopeBuilder = ModuleScopeBuilder<NativeArch, ActiveTlsResolver>;

impl Manager {
    #[inline]
    pub(crate) fn global_values(&self) -> impl Iterator<Item = LoadedDylib> + '_ {
        self.global
            .iter()
            .filter_map(|id| self.loaded_by_module(*id))
    }

    #[inline]
    pub(crate) fn main_library(&self) -> Option<ElfLibrary> {
        let id = self.link_ctx.load_order().next()?;
        let lib = self.loaded_by_module(id)?;
        let deps = self.library_scope_by_module(id)?;
        Some(ElfLibrary { inner: lib, deps })
    }

    pub(crate) fn relocation_scope(
        &self,
        group_scope: &DlopenModuleScope,
        flags: OpenFlags,
    ) -> DlopenModuleScope {
        let mut seen = BTreeSet::new();
        let mut scope = Vec::with_capacity(group_scope.len() + self.global.len());
        let mut push_unique = |module: DlopenModuleHandle| {
            if seen.insert(module.name().to_owned()) {
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

        let mut builder = DlopenModuleScopeBuilder::new();
        builder.extend(scope);
        builder.into_scope()
    }

    pub(crate) fn visible_key(&self, name: &str) -> Option<String> {
        let lookup = self.lookup(name)?;
        self.link_ctx
            .contains_key(lookup.name())
            .then(|| lookup.name().to_owned())
    }

    pub(crate) fn visible_direct_deps(&self, name: &str) -> Option<Box<[String]>> {
        let lookup = self.lookup(name)?;
        let id = self.committed_module(lookup.name())?;
        Some(
            self.link_ctx
                .direct_deps(id)
                .ok()?
                .map(|(dep_key, _)| {
                    self.link_ctx
                        .key(dep_key)
                        .expect("direct dependency id must resolve in global link context")
                        .clone()
                })
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        )
    }

    pub(crate) fn visible_loaded(&self, name: &str) -> Option<LoadedDylib> {
        let lookup = self.lookup(name)?;
        self.committed_module(lookup.name())
            .and_then(|id| self.loaded_by_module(id))
    }

    pub(crate) fn open_existing(
        &mut self,
        shortname: &str,
        flags: OpenFlags,
    ) -> Option<ElfLibrary> {
        self.promote(shortname, flags);
        self.get_lib(shortname)
    }

    pub(crate) fn get_lib(&mut self, name: &str) -> Option<ElfLibrary> {
        let lookup = self.lookup(name)?;
        let id = self.committed_module(lookup.name())?;
        let deps = self.library_scope_by_module(id)?;
        let inner = self.loaded_by_module(id)?;
        Some(ElfLibrary { inner, deps })
    }

    pub(crate) fn library_scope(&self, name: &str) -> Option<Arc<[LoadedDylib]>> {
        let lookup = self.lookup(name)?;
        let id = self.committed_module(lookup.name())?;
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
