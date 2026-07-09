use super::get_env;
#[cfg(not(feature = "std"))]
use crate::core_impl::reserve_pending;
use crate::{
    OpenFlags,
    core_impl::{
        ActiveTlsResolver, ElfLibrary, ExtraData, GlobalMeta, LibraryLookup, LoadedDylib, MANAGER,
        Manager,
    },
};
#[cfg(not(feature = "std"))]
use alloc::borrow::ToOwned;
use alloc::{collections::BTreeSet, string::String, sync::Arc};
use core::cell::RefCell;
use elf_loader::linker::{LinkContext, ModuleId};
use elf_loader::{arch::NativeArch, image::ModuleScope};
use spin::RwLockWriteGuard;

/// The context for a `dlopen` operation.
///
/// Manages the acquisition of the global lock, tracking of newly loaded libraries,
/// and handling resource cleanup if the operation fails.
pub(super) struct OpenShared<'a> {
    /// The write lock guard for the global library manager.
    /// Can be temporarily dropped to avoid deadlocks during relocation.
    lock: RefCell<Option<RwLockWriteGuard<'a, Manager>>>,
    /// Loading flags for this operation.
    pub(super) flags: OpenFlags,
}

pub(crate) struct OpenContext<'a> {
    pub(super) shared: OpenShared<'a>,
    /// Names of libraries that were added to the global registry in this operation.
    pub(super) added_names: BTreeSet<String>,
    /// Indicates if the operation was successfully committed.
    committed: bool,
}

pub(crate) enum LinkRoot<'bytes> {
    Load {
        key: String,
        bytes: Option<&'bytes [u8]>,
    },
    #[cfg(not(feature = "std"))]
    Mapped {
        key: String,
        raw: crate::core_impl::ElfDylib,
    },
}

impl<'bytes> LinkRoot<'bytes> {
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

impl<'a> Drop for OpenContext<'a> {
    fn drop(&mut self) {
        // If not committed, roll back changes to the global registry.
        if !self.committed {
            log::debug!("Destroying newly added dynamic libraries from the global");
            let mut lock = self
                .shared
                .lock
                .borrow_mut()
                .take()
                .unwrap_or_else(|| crate::lock_write!(MANAGER));
            self.remove_added_libraries(&mut lock);
        }
    }
}

impl<'a> OpenContext<'a> {
    pub(crate) fn new(mut flags: OpenFlags) -> Self {
        if get_env("LD_BIND_NOW").is_some() {
            flags |= OpenFlags::RTLD_NOW;
        }
        let lock = crate::lock_write!(MANAGER);
        Self {
            shared: OpenShared {
                lock: RefCell::new(Some(lock)),
                flags,
            },
            added_names: BTreeSet::new(),
            committed: false,
        }
    }
}

impl<'a> OpenShared<'a> {
    pub(super) fn with_manager<T>(&self, f: impl FnOnce(&Manager) -> T) -> T {
        let lock = self.lock.borrow();
        let manager = lock.as_ref().expect("Lock must be held");
        f(manager)
    }

    pub(super) fn with_manager_mut<T>(&self, f: impl FnOnce(&mut Manager) -> T) -> T {
        let mut lock = self.lock.borrow_mut();
        let manager = lock.as_mut().expect("Lock must be held");
        f(manager)
    }

    fn take_lock(&self) -> Option<RwLockWriteGuard<'a, Manager>> {
        self.lock.borrow_mut().take()
    }

    fn replace_lock(&self, lock: RwLockWriteGuard<'a, Manager>) {
        *self.lock.borrow_mut() = Some(lock);
    }

    fn wait_for_other_thread(&self) {
        drop(self.take_lock());
        core::hint::spin_loop();
        self.replace_lock(crate::lock_write!(MANAGER));
    }

    pub(super) fn lookup(
        &self,
        added_names: Option<&BTreeSet<String>>,
        path: impl AsRef<str>,
        shortname: &str,
    ) -> Option<LibraryLookup<'static>> {
        let path = path.as_ref();
        let mut req_identity = None;

        let (entry, matched_identity) = loop {
            let entry = self.with_manager(|manager| {
                if let Some(lib) = manager.lookup(shortname) {
                    return Some((lib.into_owned(), None));
                }

                if req_identity.is_none() {
                    req_identity = crate::os::get_file_inode(path).ok();
                }
                let identity = req_identity.as_ref()?;
                let lib = manager.lookup_by_identity(identity)?;
                Some((lib.into_owned(), Some(*identity)))
            });

            match entry {
                Some((lib, matched_identity))
                    if lib.is_relocated()
                        || added_names.is_some_and(|names| names.contains(lib.name())) =>
                {
                    break (Some(lib), matched_identity);
                }
                Some(_) => self.wait_for_other_thread(),
                None => break (None, None),
            }
        };

        if let (Some(lib), Some(identity)) = (entry.as_ref(), matched_identity.as_ref()) {
            log::info!(
                "dlopen: Found existing library by inode match: requested [{}], existing [{}] (dev={}, ino={})",
                shortname,
                lib.name(),
                identity.dev,
                identity.ino
            );
            self.with_manager_mut(|manager| {
                manager.add_alias(lib.name(), shortname);
            });
        }

        entry
    }

    pub(super) fn prepare_relocation(
        &self,
        group_scope: &ModuleScope<NativeArch, ActiveTlsResolver>,
    ) -> ModuleScope<NativeArch, ActiveTlsResolver> {
        let relocation_scope =
            self.with_manager_mut(|manager| manager.relocation_scope(group_scope, self.flags));
        drop(self.take_lock());
        relocation_scope
    }
}

impl<'a> OpenContext<'a> {
    fn remove_added_libraries(&self, manager: &mut Manager) {
        for name in self.added_names.iter() {
            if manager.lookup(name).is_some() {
                manager.remove(name);
            }
        }
    }

    #[cfg(not(feature = "std"))]
    pub(super) fn reserve_root_if_needed(&mut self, root: &LinkRoot<'_>) {
        if let LinkRoot::Mapped { key, raw } = root {
            let shortname = self.shared.with_manager_mut(|manager| {
                reserve_pending(key.to_owned(), raw.name(), None, self.shared.flags, manager)
            });
            self.added_names.insert(shortname);
        }
    }

    pub(super) fn finish_existing(
        &mut self,
        path: &str,
        lib: LibraryLookup<'static>,
    ) -> ElfLibrary {
        let shortname = lib.name();
        log::info!(
            "dlopen: Found existing library [{}] (canonical name: {})",
            path,
            shortname
        );
        let elf_lib = self.shared.with_manager_mut(|manager| {
            manager
                .open_existing(shortname, self.shared.flags)
                .expect("Existing library must be retrievable")
        });
        self.committed = true;
        elf_lib
    }

    pub(super) fn try_existing(&mut self, path: &str) -> Option<ElfLibrary> {
        let shortname = path.rsplit_once('/').map_or(path, |(_, name)| name);
        // Step 1: fast name/alias lookup — no stat.
        // Step 2: on miss, stat once and fall back to inode lookup.
        self.shared
            .lookup(None, path, shortname)
            .map(|lib| self.finish_existing(path, lib))
    }

    pub(super) fn complete_relocation(
        &mut self,
        link_ctx: &LinkContext<String, ExtraData, GlobalMeta, NativeArch, ActiveTlsResolver>,
        committed: impl IntoIterator<Item = ModuleId>,
    ) {
        let mut lock = self
            .shared
            .take_lock()
            .unwrap_or_else(|| crate::lock_write!(MANAGER));
        lock.merge_link_context(link_ctx, committed, self.shared.flags);
        self.shared.replace_lock(lock);
    }

    pub(super) fn library_scope(&self, root: &str) -> Arc<[LoadedDylib]> {
        self.shared.with_manager(|manager| {
            manager
                .library_scope(root)
                .expect("root library must have a dependency scope after linking")
        })
    }

    /// Finalizes the operation and returns the `ElfLibrary`.
    pub(super) fn finish(mut self, deps: Arc<[LoadedDylib]>) -> ElfLibrary {
        self.committed = true;
        let core = deps[0].clone();
        ElfLibrary { inner: core, deps }
    }
}
