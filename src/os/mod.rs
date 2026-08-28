#[cfg(feature = "use-syscall")]
mod linux;
#[cfg(feature = "use-syscall")]
pub(crate) use linux::read_file;

#[cfg(all(not(feature = "use-syscall"), unix, feature = "std"))]
pub(crate) fn read_file(path: &str) -> crate::Result<alloc::boxed::Box<[u8]>> {
    std::fs::read(path)
        .map(Vec::into_boxed_slice)
        .map_err(crate::Error::from)
}

#[cfg(not(any(feature = "use-syscall", all(unix, feature = "std"))))]
pub(crate) fn read_file(_path: &str) -> crate::Result<alloc::boxed::Box<[u8]>> {
    Err(crate::Error::Unsupported)
}
