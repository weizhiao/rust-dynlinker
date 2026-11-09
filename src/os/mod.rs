#[cfg(feature = "use-syscall")]
mod linux;
#[cfg(feature = "use-syscall")]
pub(crate) use linux::executable_dir;

#[cfg(all(not(feature = "use-syscall"), unix, feature = "std"))]
pub(crate) fn executable_dir(
    executable: Option<&elf_loader::input::Path>,
) -> Option<elf_loader::input::PathBuf> {
    use std::os::unix::ffi::OsStrExt;

    let executable = match executable {
        Some(path) => std::fs::canonicalize(std::ffi::OsStr::from_bytes(path.as_bytes())),
        None => std::env::current_exe(),
    }
    .ok()?;
    Some(elf_loader::input::Path::new(executable.parent()?.as_os_str()).into())
}

#[cfg(not(any(feature = "use-syscall", all(unix, feature = "std"))))]
pub(crate) fn executable_dir(
    _executable: Option<&elf_loader::input::Path>,
) -> Option<elf_loader::input::PathBuf> {
    None
}

#[cfg(all(not(feature = "use-syscall"), unix, feature = "std"))]
pub(crate) fn read_file(path: &str) -> crate::Result<alloc::boxed::Box<[u8]>> {
    std::fs::read(path)
        .map(Vec::into_boxed_slice)
        .map_err(crate::Error::from)
}

#[cfg(all(feature = "std", not(any(feature = "use-syscall", unix))))]
pub(crate) fn read_file(_path: &str) -> crate::Result<alloc::boxed::Box<[u8]>> {
    Err(crate::Error::Unsupported)
}
