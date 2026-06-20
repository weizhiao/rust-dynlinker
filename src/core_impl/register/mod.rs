mod lifecycle;
mod manager;

pub(crate) use lifecycle::{addr2dso, global_find, next_find, register_loaded, reserve_pending};

use super::{
    loader::{ActiveTlsResolver, LoadedDylib},
    types::{ExtraData, FileIdentity},
};
use crate::OpenFlags;
use alloc::{borrow::Cow, string::String, vec::Vec};
use elf_loader::{
    arch::NativeArch,
    linker::{LinkContext, ModuleId},
};
use hashbrown::{DefaultHashBuilder, HashMap};
use spin::{Lazy, RwLock};

type IndexMap<K, V> = indexmap::IndexMap<K, V, DefaultHashBuilder>;
type IndexSet<K> = indexmap::IndexSet<K, DefaultHashBuilder>;
type GlobalLinkContext = LinkContext<String, ExtraData, GlobalMeta, NativeArch, ActiveTlsResolver>;

#[macro_export]
macro_rules! lock_write {
    ($lock:expr) => {{ $lock.write() }};
}

#[macro_export]
macro_rules! lock_read {
    ($lock:expr) => {{ $lock.read() }};
}

#[derive(Clone)]
pub(crate) struct PendingDylib {
    shortname: String,
    inner: Option<LoadedDylib>,
    pub(crate) flags: OpenFlags,
    pub(crate) libnames: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct PendingModuleId(usize);

impl PendingModuleId {
    #[inline]
    fn new(index: usize) -> Self {
        Self(index)
    }
}

unsafe impl Send for PendingDylib {}
unsafe impl Sync for PendingDylib {}

impl PendingDylib {
    fn reserved(shortname: String, flags: OpenFlags) -> Self {
        Self {
            shortname,
            inner: None,
            flags,
            libnames: Vec::new(),
        }
    }

    #[inline]
    fn shortname(&self) -> &str {
        &self.shortname
    }

    #[inline]
    fn dylib(&self) -> Option<LoadedDylib> {
        self.inner.clone()
    }

    #[inline]
    fn dylib_ref(&self) -> Option<&LoadedDylib> {
        self.inner.as_ref()
    }
}

#[derive(Clone)]
pub(crate) struct LibraryLookup<'a> {
    shortname: Cow<'a, str>,
    relocated: bool,
}

impl<'a> LibraryLookup<'a> {
    pub(crate) fn pending(shortname: Cow<'a, str>) -> Self {
        Self {
            shortname,
            relocated: false,
        }
    }

    pub(crate) fn relocated(shortname: Cow<'a, str>) -> Self {
        Self {
            shortname,
            relocated: true,
        }
    }

    pub(crate) fn is_relocated(&self) -> bool {
        self.relocated
    }

    pub(crate) fn shortname(&self) -> &str {
        &self.shortname
    }

    pub(crate) fn into_owned(self) -> LibraryLookup<'static> {
        LibraryLookup {
            shortname: Cow::Owned(self.shortname.into_owned()),
            relocated: self.relocated,
        }
    }
}

#[derive(Clone)]
pub(crate) struct GlobalMeta {
    pub(crate) flags: OpenFlags,
    pub(crate) libnames: Vec<String>,
}

impl Default for GlobalMeta {
    #[inline]
    fn default() -> Self {
        Self {
            flags: OpenFlags::empty(),
            libnames: Vec::new(),
        }
    }
}

/// The global manager for all loaded dynamic libraries.
pub(crate) struct Manager {
    /// Libraries that are visible to concurrent `dlopen` calls but are not yet
    /// committed to the dependency graph.
    pending: IndexMap<PendingModuleId, PendingDylib>,
    /// Visible names for pending libraries, indexed by canonical name/alias -> pending module.
    pending_keys: HashMap<String, PendingModuleId>,
    pending_next_id: usize,
    /// Libraries available in the global symbol scope (RTLD_GLOBAL).
    global: IndexSet<ModuleId>,
    /// Maps file identities to the canonical short name for fast inode-based lookup.
    identities: HashMap<FileIdentity, String>,
    /// Fully linked modules indexed by canonical key.
    link_ctx: GlobalLinkContext,
    /// The number of times a new object has been added to the link map.
    adds: u64,
    /// The number of times an object has been removed from the link map.
    subs: u64,
}

/// The global static instance of the library manager, protected by a readers-writer lock.
pub(crate) static MANAGER: Lazy<RwLock<Manager>> = Lazy::new(|| {
    RwLock::new(Manager {
        pending: IndexMap::with_hasher(DefaultHashBuilder::default()),
        pending_keys: HashMap::new(),
        pending_next_id: 0,
        global: IndexSet::with_hasher(DefaultHashBuilder::default()),
        identities: HashMap::new(),
        link_ctx: LinkContext::new(),
        adds: 0,
        subs: 0,
    })
});

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

fn libc_compat_aliases(shortname: &str) -> &'static [&'static str] {
    match shortname {
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
