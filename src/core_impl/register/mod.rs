mod lifecycle;
mod manager;

pub(crate) use lifecycle::{addr2dso, global_find, next_find, register_loaded, reserve_pending};

use super::{
    loader::LoadedDylib,
    types::{ExtraData, FileIdentity},
};
use crate::OpenFlags;
use alloc::{borrow::Cow, string::String, vec::Vec};
use elf_loader::linker::{LinkContext, ModuleId};
use hashbrown::{DefaultHashBuilder, HashMap};
use spin::{Lazy, RwLock};

type IndexMap<K, V> = indexmap::IndexMap<K, V, DefaultHashBuilder>;
type IndexSet<K> = indexmap::IndexSet<K, DefaultHashBuilder>;

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
    inner: Option<LoadedDylib>,
    pub(crate) flags: OpenFlags,
    pub(crate) libnames: Vec<String>,
}

unsafe impl Send for PendingDylib {}
unsafe impl Sync for PendingDylib {}

impl PendingDylib {
    fn reserved(flags: OpenFlags) -> Self {
        Self {
            inner: None,
            flags,
            libnames: Vec::new(),
        }
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
pub(crate) enum LibraryLookup<'a> {
    Pending {
        shortname: Cow<'a, str>,
    },
    Relocated {
        shortname: Cow<'a, str>,
        name: Cow<'a, str>,
    },
}

impl<'a> LibraryLookup<'a> {
    pub(crate) fn is_relocated(&self) -> bool {
        matches!(self, Self::Relocated { .. })
    }

    pub(crate) fn shortname(&self) -> &str {
        match self {
            Self::Pending { shortname } | Self::Relocated { shortname, .. } => shortname,
        }
    }

    pub(crate) fn name(&self) -> Option<&str> {
        match self {
            Self::Relocated { name, .. } => Some(name),
            Self::Pending { .. } => None,
        }
    }

    pub(crate) fn into_owned(self) -> LibraryLookup<'static> {
        match self {
            Self::Pending { shortname } => LibraryLookup::Pending {
                shortname: Cow::Owned(shortname.into_owned()),
            },
            Self::Relocated { shortname, name } => LibraryLookup::Relocated {
                shortname: Cow::Owned(shortname.into_owned()),
                name: Cow::Owned(name.into_owned()),
            },
        }
    }

    pub(crate) fn into_shortname_owned(self) -> String {
        match self {
            Self::Pending { shortname } | Self::Relocated { shortname, .. } => {
                shortname.into_owned()
            }
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
    pending: IndexMap<String, PendingDylib>,
    /// Libraries available in the global symbol scope (RTLD_GLOBAL).
    global: IndexSet<ModuleId>,
    /// Maps file identities to the canonical short name for fast inode-based lookup.
    identities: HashMap<FileIdentity, String>,
    /// Fully linked modules indexed by canonical key.
    link_ctx: LinkContext<String, ExtraData, GlobalMeta>,
    /// The number of times a new object has been added to the link map.
    adds: u64,
    /// The number of times an object has been removed from the link map.
    subs: u64,
}

/// The global static instance of the library manager, protected by a readers-writer lock.
pub(crate) static MANAGER: Lazy<RwLock<Manager>> = Lazy::new(|| {
    RwLock::new(Manager {
        pending: IndexMap::with_hasher(DefaultHashBuilder::default()),
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
