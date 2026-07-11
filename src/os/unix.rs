use crate::Result;
use crate::registry::FileIdentity;
use alloc::boxed::Box;

pub(crate) fn read_file(path: &str) -> Result<Box<[u8]>> {
    std::fs::read(path)
        .map(|v| v.into_boxed_slice())
        .map_err(crate::Error::from)
}

pub(crate) fn read_file_limit(path: &str, limit: usize) -> Result<Box<[u8]>> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut buf = alloc::vec![0; limit];
    let n = file.read(&mut buf)?;
    buf.truncate(n);
    Ok(buf.into_boxed_slice())
}

pub(crate) fn get_file_identity(fd: isize) -> Result<FileIdentity> {
    let mut stat: libc::stat = unsafe { core::mem::zeroed() };
    if unsafe { libc::fstat(fd as libc::c_int, &mut stat) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(FileIdentity {
        dev: stat.st_dev,
        ino: stat.st_ino,
    })
}
