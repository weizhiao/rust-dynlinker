use crate::Error;
use alloc::string::ToString;

pub(crate) fn executable_dir(
    executable: Option<&elf_loader::input::Path>,
) -> Option<elf_loader::input::PathBuf> {
    use alloc::{ffi::CString, format};
    use elf_loader::input::Path;

    const AT_FDCWD: usize = -100isize as usize;
    const O_PATH: usize = 0o10000000;
    const O_CLOEXEC: usize = 0o2000000;

    // Direct rtld invocation must resolve the program, since /proc/self/exe then
    // names the interpreter. The fd link also resolves relative paths/symlinks.
    let fd = if let Some(executable) = executable {
        let path = CString::new(executable.as_bytes()).ok()?;
        Some(unsafe {
            syscalls::syscall4(
                syscalls::Sysno::openat,
                AT_FDCWD,
                path.as_ptr() as usize,
                O_PATH | O_CLOEXEC,
                0,
            )
            .ok()?
        })
    } else {
        None
    };
    let fd_path = fd.map(|fd| format!("/proc/self/fd/{fd}\0"));
    let path = fd_path
        .as_ref()
        .map_or(c"/proc/self/exe".as_ptr().cast::<u8>(), |path| {
            path.as_ptr()
        });
    let mut buffer = [0u8; 4096];
    let result = unsafe {
        syscalls::syscall4(
            syscalls::Sysno::readlinkat,
            AT_FDCWD,
            path as usize,
            buffer.as_mut_ptr() as usize,
            buffer.len(),
        )
    };
    if let Some(fd) = fd {
        let _ = unsafe { syscalls::syscall1(syscalls::Sysno::close, fd) };
    }
    let len = result.ok()?;
    if len == 0 || len >= buffer.len() {
        return None;
    }
    // Linux permits backslashes in filenames; only '/' separates directories.
    let slash = buffer[..len].iter().rposition(|byte| *byte == b'/')?;
    Some(Path::new(&buffer[..slash.max(1)]).into())
}

impl From<syscalls::Errno> for Error {
    fn from(value: syscalls::Errno) -> Self {
        Error::IO(value.to_string())
    }
}
