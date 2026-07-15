use super::run::get_env;
use crate::{
    OpenFlags,
    image::{ElfLibrary, LoadedDylib},
    registry::{FileIdentity, GlobalLinkContext, GlobalMeta, RegistryGuard, libc_compat_aliases},
};
use alloc::{borrow::ToOwned, collections::BTreeMap, rc::Rc, string::String, vec::Vec};
use core::cell::RefCell;
use elf_loader::linker::ModuleId;

/// Metadata staged while one serialized `dlopen` transaction is prepared.
pub(crate) struct OpenContext {
    pub(super) flags: OpenFlags,
    pub(super) staged: Rc<RefCell<StagedModules>>,
}

pub(super) struct StagedModules {
    entries: BTreeMap<String, GlobalMeta>,
    aliases: Vec<(String, String)>,
}

impl StagedModules {
    fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            aliases: Vec::new(),
        }
    }

    pub(super) fn lookup(&self, name: &str, identity: Option<FileIdentity>) -> Option<&str> {
        self.entries
            .iter()
            .find(|(key, meta)| meta.matches(key, name, identity))
            .map(|(key, _)| key.as_str())
    }

    pub(super) fn reserve(
        &mut self,
        name: String,
        full_name: &str,
        identity: Option<FileIdentity>,
        flags: OpenFlags,
    ) {
        if self.lookup(&name, identity).is_some() {
            return;
        }

        let metadata = GlobalMeta::loading(full_name, identity, flags);
        let previous = self.entries.insert(name, metadata);
        debug_assert!(previous.is_none(), "staged module inserted twice");
    }

    pub(super) fn add_alias(&mut self, target: String, alias: String) {
        if target != alias
            && !self
                .aliases
                .iter()
                .any(|(existing_target, existing_alias)| {
                    existing_target == &target && existing_alias == &alias
                })
        {
            self.aliases.push((target, alias));
        }
    }

    fn apply(&self, link_ctx: &mut GlobalLinkContext, committed: &[ModuleId]) {
        for &id in committed {
            let Ok(key) = link_ctx.module_key(id).cloned() else {
                continue;
            };
            let Some(metadata) = self.entries.get(&key).cloned() else {
                continue;
            };
            let loaded = link_ctx
                .get(id)
                .ok()
                .and_then(|module| module.downcast_ref::<LoadedDylib>())
                .cloned();
            *link_ctx
                .meta_mut(id)
                .expect("staged module must have metadata") = metadata;

            let mut add_alias = |alias: &str| {
                if !alias.is_empty() && alias != key {
                    link_ctx
                        .add_alias(id, alias.to_owned())
                        .expect("staged alias must target its module");
                }
            };
            if let Some(lib) = loaded.as_ref() {
                add_alias(lib.name());
                add_alias(lib.path().file_name());
            }
            for alias in libc_compat_aliases(&key) {
                add_alias(alias);
            }
        }

        for (target, alias) in &self.aliases {
            let target = link_ctx
                .key_id(target)
                .and_then(|id| link_ctx.module_id(id).ok().flatten())
                .expect("staged alias target must remain committed");
            link_ctx
                .add_alias(target, alias.clone())
                .expect("staged alias must target its committed module");
        }
    }
}

pub(crate) enum LinkRoot<'bytes> {
    Load {
        key: String,
        bytes: Option<&'bytes [u8]>,
    },
    #[cfg(not(feature = "std"))]
    Mapped {
        key: String,
        raw: crate::image::ElfDylib,
    },
}

impl<'bytes> LinkRoot<'bytes> {
    pub(super) fn key(&self) -> &str {
        match self {
            Self::Load { key, .. } => key,
            #[cfg(not(feature = "std"))]
            Self::Mapped { key, .. } => key,
        }
    }

    pub(super) fn reuse_existing(&self) -> bool {
        matches!(self, Self::Load { .. })
    }

    pub(super) fn source(&self) -> CandidateSource<'bytes> {
        match self {
            Self::Load { bytes, .. } => CandidateSource::from(*bytes),
            #[cfg(not(feature = "std"))]
            Self::Mapped { .. } => CandidateSource::File,
        }
    }
}

#[derive(Clone, Copy)]
pub(super) enum CandidateSource<'bytes> {
    File,
    Bytes(&'bytes [u8]),
}

impl<'bytes> From<Option<&'bytes [u8]>> for CandidateSource<'bytes> {
    fn from(bytes: Option<&'bytes [u8]>) -> Self {
        match bytes {
            Some(bytes) => Self::Bytes(bytes),
            None => Self::File,
        }
    }
}

impl OpenContext {
    pub(crate) fn new(mut flags: OpenFlags) -> Self {
        if get_env("LD_BIND_NOW").is_some() {
            flags |= OpenFlags::RTLD_NOW;
        }
        Self {
            flags,
            staged: Rc::new(RefCell::new(StagedModules::new())),
        }
    }

    #[cfg(not(feature = "std"))]
    pub(super) fn reserve_root_if_needed(&self, root: &LinkRoot<'_>) {
        if let LinkRoot::Mapped { key, raw } = root {
            self.staged
                .borrow_mut()
                .reserve(key.to_owned(), raw.name(), None, self.flags);
        }
    }

    pub(super) fn try_existing(
        &self,
        registry: &RegistryGuard<'_>,
        path: &str,
    ) -> Option<ElfLibrary> {
        let name = path.rsplit_once('/').map_or(path, |(_, name)| name);
        // Step 1: fast name/alias lookup — no stat.
        let name = registry.borrow().lookup(name).map(ToOwned::to_owned)?;
        log::info!(
            "dlopen: Found existing library [{}] (canonical name: {})",
            path,
            name
        );
        let lib = registry
            .borrow_mut()
            .open_existing(&name, self.flags)
            .expect("Existing library must be retrievable");
        Some(lib)
    }

    pub(super) fn register(
        self,
        registry: &RegistryGuard<'_>,
        committed: &[ModuleId],
        root: ModuleId,
    ) -> ElfLibrary {
        {
            let mut manager = registry.borrow_mut();
            self.staged.borrow().apply(manager.context_mut(), committed);
        }
        registry.register_committed(committed);
        registry
            .borrow_mut()
            .open_module(root)
            .expect("linked root module must be registered")
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::StagedModules;
    use crate::{OpenFlags, registry::FileIdentity};

    #[test]
    fn staged_modules_deduplicate_file_identity() {
        let identity = Some(FileIdentity { dev: 1, ino: 2 });
        let mut staged = StagedModules::new();
        staged.reserve(
            "liboriginal.so".into(),
            "/tmp/liboriginal.so",
            identity,
            OpenFlags::RTLD_NOW,
        );
        staged.reserve(
            "libalias.so".into(),
            "/tmp/libalias.so",
            identity,
            OpenFlags::RTLD_NOW,
        );

        assert_eq!(staged.entries.len(), 1);
        assert_eq!(
            staged.lookup("libalias.so", identity),
            Some("liboriginal.so")
        );
    }
}
