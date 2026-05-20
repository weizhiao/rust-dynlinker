use super::context::{CandidateSource, OpenShared};
use super::{
    DEFAULT_PATH, LD_CACHE, LD_LIBRARY_PATH, fixup_rpath, is_elf_input,
    should_continue_library_search,
};
use crate::{
    Result,
    core_impl::{ExtraData, reserve_pending},
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
use elf_loader::image::ModuleHandle;
use elf_loader::input::{ElfBinary, ElfFile, ElfReader, PathBuf as ElfPath};
use elf_loader::linker::{
    DependencyRequest, KeyResolver, ResolvedKey, RootRequest, VisibleModules,
};

fn into_linker_error(err: crate::error::Error) -> elf_loader::Error {
    match err {
        crate::error::Error::LoaderError { err } => err,
        other => elf_loader::CustomError::Message(other.to_string().into()).into(),
    }
}

pub(super) struct LinkResolver<'ctx, 'mgr, 'bytes> {
    shared: &'ctx OpenShared<'mgr>,
    added_names: &'ctx mut BTreeSet<String>,
    root_request: String,
    root_source: CandidateSource<'bytes>,
}

pub(super) struct DlopenVisible<'ctx, 'mgr> {
    shared: &'ctx OpenShared<'mgr>,
}

impl<'ctx, 'mgr> DlopenVisible<'ctx, 'mgr> {
    pub(super) fn new(shared: &'ctx OpenShared<'mgr>) -> Self {
        Self { shared }
    }
}

impl VisibleModules<String, ExtraData> for DlopenVisible<'_, '_> {
    fn contains_key(&self, key: &String) -> bool {
        self.shared
            .with_manager(|manager| manager.visible_contains(key))
    }

    fn direct_deps(&self, key: &String) -> Option<Box<[String]>> {
        self.shared
            .with_manager(|manager| manager.visible_direct_deps(key))
    }

    fn module(&self, key: &String) -> Option<ModuleHandle> {
        self.shared
            .with_manager(|manager| manager.visible_loaded(key).map(Into::into))
    }
}

enum CandidateInput<'bytes> {
    Reader(Box<dyn ElfReader + 'bytes>),
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

    fn contains_visible(self, shortname: &str) -> bool {
        self.visible.is_some_and(|is_visible| is_visible(shortname))
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
            added_names,
            root_request: root_request.to_owned(),
            root_source,
        }
    }

    fn reserve_pending(&mut self, path: &ElfPath) {
        let shortname = path.file_name();
        if self.added_names.contains(shortname) {
            return;
        }

        let identity = crate::os::get_file_inode(path).ok();
        let shortname = self.shared.with_manager_mut(|manager| {
            reserve_pending(
                shortname.to_owned(),
                path.as_str(),
                identity,
                self.shared.flags,
                manager,
            )
        });
        self.added_names.insert(shortname);
    }

    fn resolve_existing(
        &self,
        path: &ElfPath,
        env: ResolveEnv<'_>,
    ) -> Option<ResolvedKey<'static, String>> {
        let shortname = path.file_name();
        if env.contains_visible(shortname) {
            return Some(ResolvedKey::existing(shortname.to_owned()));
        }

        self.shared
            .lookup(Some(&*self.added_names), path.as_str(), shortname)
            .map(|lib| ResolvedKey::existing(lib.into_shortname_owned()))
    }

    fn resolve_script(
        &mut self,
        env: ResolveEnv<'_>,
        libs: Vec<String>,
    ) -> Result<ResolvedKey<'bytes, String>> {
        self.resolve_first(libs, |resolver, lib| {
            resolver.resolve_request(env, &lib, CandidateSource::File)
        })?
        .ok_or_else(|| find_lib_error("can not resolve linker script".to_string()))
    }

    fn resolve_candidate_path(
        &mut self,
        env: ResolveEnv<'_>,
        path: &ElfPath,
        source: CandidateSource<'bytes>,
    ) -> Result<ResolvedKey<'bytes, String>> {
        let shortname = path.file_name();
        if let Some(module) = self.resolve_existing(path, env) {
            return Ok(module);
        }

        match self.load_candidate(path.as_str(), source)? {
            CandidateInput::Reader(reader) => {
                self.reserve_pending(path);
                Ok(ResolvedKey::load(shortname.to_owned(), reader))
            }
            CandidateInput::Script(libs) => self.resolve_script(env, libs),
        }
    }

    fn load_candidate(
        &self,
        path: &str,
        source: CandidateSource<'bytes>,
    ) -> Result<CandidateInput<'bytes>> {
        match source {
            CandidateSource::Bytes(bytes) => self.load_candidate_bytes(path, bytes),
            CandidateSource::File => self.load_candidate_file(path),
        }
    }

    fn load_candidate_bytes(
        &self,
        path: &str,
        bytes: &'bytes [u8],
    ) -> Result<CandidateInput<'bytes>> {
        if is_elf_input(bytes) {
            Ok(CandidateInput::Reader(Box::new(ElfBinary::new(
                path, bytes,
            ))))
        } else {
            Ok(CandidateInput::Script(get_linker_script_libs(bytes)))
        }
    }

    fn load_candidate_file(&self, path: &str) -> Result<CandidateInput<'bytes>> {
        let header = crate::os::read_file_limit(path, 64)?;
        if is_elf_input(&header) {
            Ok(CandidateInput::Reader(Box::new(ElfFile::from_path(path)?)))
        } else {
            let content = crate::os::read_file(path)?;
            Ok(CandidateInput::Script(get_linker_script_libs(&content)))
        }
    }

    fn resolve_first<Candidate>(
        &mut self,
        candidates: impl IntoIterator<Item = Candidate>,
        mut resolve: impl FnMut(&mut Self, Candidate) -> Result<ResolvedKey<'bytes, String>>,
    ) -> Result<Option<ResolvedKey<'bytes, String>>> {
        for candidate in candidates {
            match resolve(self, candidate) {
                Ok(module) => return Ok(Some(module)),
                Err(err) if should_continue_library_search(&err) => {}
                Err(err) => return Err(err),
            }
        }
        Ok(None)
    }

    fn resolve_search_paths(
        &mut self,
        env: ResolveEnv<'_>,
        paths: impl IntoIterator<Item = ElfPath>,
        source: CandidateSource<'bytes>,
    ) -> Result<Option<ResolvedKey<'bytes, String>>> {
        self.resolve_first(paths, |resolver, path| {
            resolver.resolve_candidate_path(env, &path, source)
        })
    }

    fn resolve_request(
        &mut self,
        env: ResolveEnv<'_>,
        lib_name: &str,
        source: CandidateSource<'bytes>,
    ) -> Result<ResolvedKey<'bytes, String>> {
        if lib_name.contains('/') {
            let path = ElfPath::from(lib_name);
            return self.resolve_candidate_path(env, &path, source);
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
            self.resolve_search_paths(env, search_dirs.map(|dir| dir.join(lib_name)), source)?
        {
            return Ok(module);
        }

        if let Some(cached_path) = LD_CACHE
            .as_ref()
            .and_then(|cache| cache.lookup(lib_name))
            .map(ElfPath::from)
        {
            match self.resolve_candidate_path(env, &cached_path, source) {
                Ok(module) => return Ok(module),
                Err(err) if should_continue_library_search(&err) => {}
                Err(err) => return Err(err),
            }
        }

        if let Some(module) = self.resolve_search_paths(
            env,
            DEFAULT_PATH.iter().map(|dir| dir.join(lib_name)),
            source,
        )? {
            return Ok(module);
        }

        Err(find_lib_error(format!(
            "can not find library: {}",
            lib_name
        )))
    }
}

impl<'ctx, 'mgr, 'bytes> KeyResolver<'bytes, String> for LinkResolver<'ctx, 'mgr, 'bytes> {
    fn load_root(
        &mut self,
        req: &RootRequest<'_, String>,
    ) -> core::result::Result<ResolvedKey<'bytes, String>, elf_loader::Error> {
        let key = req.key();
        let source = if *key == self.root_request {
            self.root_source.take()
        } else {
            CandidateSource::File
        };
        self.resolve_request(ResolveEnv::empty(), key, source)
            .map_err(into_linker_error)
    }

    fn resolve_dependency(
        &mut self,
        req: &DependencyRequest<'_, String>,
    ) -> core::result::Result<ResolvedKey<'bytes, String>, elf_loader::Error> {
        let owner_name = req.owner_name();
        let rpath = req
            .rpath()
            .map(|r| fixup_rpath(owner_name, r))
            .unwrap_or_default();
        let runpath = req
            .runpath()
            .map(|r| fixup_rpath(owner_name, r))
            .unwrap_or_default();
        let is_visible = |key: &str| req.is_visible(&key.to_owned());
        let env = ResolveEnv::new(Some(&is_visible), &rpath, &runpath);
        self.resolve_request(env, req.needed(), CandidateSource::File)
            .map_err(into_linker_error)
    }
}
