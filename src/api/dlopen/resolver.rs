use super::context::{CandidateSource, OpenShared};
use super::{
    DEFAULT_PATH, LD_CACHE, LD_LIBRARY_PATH, fixup_rpath, is_elf_input,
    should_continue_library_search,
};
use crate::{
    Result,
    core_impl::{ActiveTlsResolver, reserve_pending},
    error::find_lib_error,
    utils::linker_script::get_linker_script_libs,
};
use alloc::{
    borrow::ToOwned,
    boxed::Box,
    collections::BTreeSet,
    format,
    string::{String, ToString},
    vec::Vec,
};
use core::cell::{Cell, RefCell};
use elf_loader::arch::NativeArch;
use elf_loader::input::{ElfBinary, ElfFile, ElfReader, PathBuf as ElfPath};
use elf_loader::linker::{
    DependencyRequest, KeyResolver, ResolvedKey, RootRequest, VisibleModule, VisibleModules,
};

type DlopenResolvedKey<'cfg> = ResolvedKey<'cfg, String, NativeArch, ActiveTlsResolver>;

fn into_linker_error(err: crate::error::Error) -> elf_loader::Error {
    match err {
        crate::error::Error::LoaderError { err } => err,
        other => elf_loader::CustomError::Message(other.to_string().into()).into(),
    }
}

pub(super) struct LinkResolver<'ctx, 'mgr, 'bytes> {
    shared: &'ctx OpenShared<'mgr>,
    added_names: RefCell<&'ctx mut BTreeSet<String>>,
    root_request: String,
    root_source: Cell<CandidateSource<'bytes>>,
}

pub(super) struct DlopenVisible<'ctx, 'mgr> {
    shared: &'ctx OpenShared<'mgr>,
}

impl<'ctx, 'mgr> DlopenVisible<'ctx, 'mgr> {
    pub(super) fn new(shared: &'ctx OpenShared<'mgr>) -> Self {
        Self { shared }
    }
}

impl VisibleModules<String, NativeArch, str, ActiveTlsResolver> for DlopenVisible<'_, '_> {
    fn contains(&self, key: &str) -> bool {
        self.shared
            .with_manager(|manager| manager.visible_key(key).is_some())
    }

    fn module(&self, key: &str) -> Option<VisibleModule<String, NativeArch, ActiveTlsResolver>> {
        self.shared.with_manager(|manager| {
            let key = manager.visible_key(key)?;
            let module = manager.visible_loaded(&key)?;
            let direct_deps = manager.visible_direct_deps(&key)?;
            Some(VisibleModule::new(module, direct_deps))
        })
    }
}

enum CandidateInput {
    Reader(Box<dyn ElfReader + 'static>),
    Script(Vec<String>),
}

#[derive(Clone, Copy)]
struct ResolveEnv<'req> {
    visible: Option<&'req dyn Fn(&str) -> bool>,
    rpath: &'req [ElfPath],
    runpath: &'req [ElfPath],
}

impl<'req> ResolveEnv<'req> {
    fn new(
        visible: Option<&'req dyn Fn(&str) -> bool>,
        rpath: &'req [ElfPath],
        runpath: &'req [ElfPath],
    ) -> Self {
        Self {
            visible,
            rpath,
            runpath,
        }
    }

    fn empty() -> Self {
        Self::new(None, &[], &[])
    }

    fn contains_visible(self, name: &str) -> bool {
        self.visible.is_some_and(|is_visible| is_visible(name))
    }
}

impl<'ctx, 'mgr, 'bytes> LinkResolver<'ctx, 'mgr, 'bytes> {
    pub(super) fn new(
        shared: &'ctx OpenShared<'mgr>,
        added_names: &'ctx mut BTreeSet<String>,
        root_request: &str,
        root_source: CandidateSource<'bytes>,
    ) -> Self {
        Self {
            shared,
            added_names: RefCell::new(added_names),
            root_request: root_request.to_owned(),
            root_source: Cell::new(root_source),
        }
    }

    fn reserve_pending(&self, path: &ElfPath) {
        let name = path.file_name();
        if self.added_names.borrow().contains(name) {
            return;
        }

        let identity = crate::os::get_file_inode(path).ok();
        let name = self.shared.with_manager_mut(|manager| {
            reserve_pending(
                name.to_owned(),
                path.as_str(),
                identity,
                self.shared.flags,
                manager,
            )
        });
        self.added_names.borrow_mut().insert(name);
    }

    fn resolve_existing(
        &self,
        path: &ElfPath,
        env: ResolveEnv<'_>,
    ) -> Option<DlopenResolvedKey<'static>> {
        let name = path.file_name();
        if env.contains_visible(name) {
            return Some(ResolvedKey::existing(name.to_owned()));
        }

        self.shared
            .lookup(Some(&*self.added_names.borrow()), path.as_str(), name)
            .map(|lib| ResolvedKey::existing(lib.name().to_owned()))
    }

    fn resolve_script(
        &self,
        env: ResolveEnv<'_>,
        libs: Vec<String>,
    ) -> Result<DlopenResolvedKey<'static>> {
        self.resolve_first(libs, |resolver, lib| resolver.resolve_request(env, &lib))?
            .ok_or_else(|| find_lib_error("can not resolve linker script".to_string()))
    }

    fn resolve_candidate_path<'cfg>(
        &self,
        env: ResolveEnv<'_>,
        path: &ElfPath,
    ) -> Result<DlopenResolvedKey<'cfg>>
    where
        String: 'cfg,
    {
        let name = path.file_name();
        if let Some(module) = self.resolve_existing(path, env) {
            return Ok(module);
        }

        match self.load_candidate_file(path.as_str())? {
            CandidateInput::Reader(reader) => {
                self.reserve_pending(path);
                Ok(ResolvedKey::load(name.to_owned(), reader))
            }
            CandidateInput::Script(libs) => Ok(self.resolve_script(env, libs)?),
        }
    }

    fn resolve_root_bytes<'cfg>(
        &self,
        key: &str,
        bytes: &'bytes [u8],
    ) -> Result<DlopenResolvedKey<'cfg>>
    where
        String: 'cfg,
    {
        let path = ElfPath::from(key);
        let env = ResolveEnv::empty();
        let name = path.file_name();
        if let Some(module) = self.resolve_existing(&path, env) {
            return Ok(module);
        }

        match self.load_candidate_bytes(path.as_str(), bytes)? {
            CandidateInput::Reader(reader) => {
                self.reserve_pending(&path);
                Ok(ResolvedKey::load(name.to_owned(), reader))
            }
            CandidateInput::Script(libs) => Ok(self.resolve_script(env, libs)?),
        }
    }

    fn load_candidate_bytes(&self, path: &str, bytes: &'bytes [u8]) -> Result<CandidateInput> {
        if is_elf_input(bytes) {
            Ok(CandidateInput::Reader(Box::new(ElfBinary::owned(
                path,
                bytes.to_vec(),
            ))))
        } else {
            Ok(CandidateInput::Script(get_linker_script_libs(bytes)))
        }
    }

    fn load_candidate_file(&self, path: &str) -> Result<CandidateInput> {
        let header = crate::os::read_file_limit(path, 64)?;
        if is_elf_input(&header) {
            Ok(CandidateInput::Reader(Box::new(ElfFile::from_path(path)?)))
        } else {
            let content = crate::os::read_file(path)?;
            Ok(CandidateInput::Script(get_linker_script_libs(&content)))
        }
    }

    fn resolve_first<'cfg, Candidate>(
        &self,
        candidates: impl IntoIterator<Item = Candidate>,
        mut resolve: impl FnMut(&Self, Candidate) -> Result<DlopenResolvedKey<'cfg>>,
    ) -> Result<Option<DlopenResolvedKey<'cfg>>> {
        for candidate in candidates {
            match resolve(self, candidate) {
                Ok(module) => return Ok(Some(module)),
                Err(err) if should_continue_library_search(&err) => {}
                Err(err) => return Err(err),
            }
        }
        Ok(None)
    }

    fn resolve_search_paths<'cfg>(
        &self,
        env: ResolveEnv<'_>,
        paths: impl IntoIterator<Item = ElfPath>,
    ) -> Result<Option<DlopenResolvedKey<'cfg>>>
    where
        String: 'cfg,
    {
        self.resolve_first(paths, |resolver, path| {
            resolver.resolve_candidate_path(env, &path)
        })
    }

    fn resolve_request<'cfg>(
        &self,
        env: ResolveEnv<'_>,
        lib_name: &str,
    ) -> Result<DlopenResolvedKey<'cfg>>
    where
        String: 'cfg,
    {
        if lib_name.contains('/') {
            let path = ElfPath::from(lib_name);
            return self.resolve_candidate_path(env, &path);
        }

        let rpath_dirs = if env.runpath.is_empty() {
            env.rpath
        } else {
            &[]
        };
        let search_dirs = rpath_dirs
            .iter()
            .chain(LD_LIBRARY_PATH.iter())
            .chain(env.runpath.iter());
        if let Some(module) =
            self.resolve_search_paths(env, search_dirs.map(|dir| dir.join(lib_name)))?
        {
            return Ok(module);
        }

        if let Some(cached_path) = LD_CACHE
            .as_ref()
            .and_then(|cache| cache.lookup(lib_name))
            .map(ElfPath::from)
        {
            match self.resolve_candidate_path(env, &cached_path) {
                Ok(module) => return Ok(module),
                Err(err) if should_continue_library_search(&err) => {}
                Err(err) => return Err(err),
            }
        }

        if let Some(module) =
            self.resolve_search_paths(env, DEFAULT_PATH.iter().map(|dir| dir.join(lib_name)))?
        {
            return Ok(module);
        }

        Err(find_lib_error(format!(
            "can not find library: {}",
            lib_name
        )))
    }
}

impl<'ctx, 'mgr, 'bytes> KeyResolver<String, NativeArch, str, ActiveTlsResolver>
    for LinkResolver<'ctx, 'mgr, 'bytes>
{
    fn load_root<'cfg>(
        &self,
        req: &RootRequest<'_, String, str>,
    ) -> core::result::Result<DlopenResolvedKey<'cfg>, elf_loader::Error>
    where
        String: 'cfg,
    {
        let key = req.key();
        let source = if *key == self.root_request {
            let source = self.root_source.get();
            self.root_source.set(CandidateSource::File);
            source
        } else {
            CandidateSource::File
        };
        match source {
            CandidateSource::File => self.resolve_request(ResolveEnv::empty(), key),
            CandidateSource::Bytes(bytes) => self.resolve_root_bytes(key, bytes),
        }
        .map_err(into_linker_error)
    }

    fn resolve_dependency<'cfg>(
        &self,
        req: &DependencyRequest<'_, String, str>,
    ) -> core::result::Result<DlopenResolvedKey<'cfg>, elf_loader::Error>
    where
        String: 'cfg,
    {
        let owner_name = req.owner_name();
        let rpath = req
            .rpath()
            .map(|r| fixup_rpath(owner_name, r))
            .unwrap_or_default();
        let runpath = req
            .runpath()
            .map(|r| fixup_rpath(owner_name, r))
            .unwrap_or_default();
        let is_visible = |key: &str| req.contains_key(key);
        let env = ResolveEnv::new(Some(&is_visible), &rpath, &runpath);
        self.resolve_request(env, req.needed())
            .map_err(into_linker_error)
    }
}
