use crate::{Error, Result};
use alloc::boxed::Box;
#[cfg(not(feature = "std"))]
use alloc::string::ToString;
use alloc::vec::Vec;

impl From<syscalls::Errno> for Error {
    fn from(value: syscalls::Errno) -> Self {
        #[cfg(feature = "std")]
        {
            Error::IO(std::io::Error::from_raw_os_error(value.into_raw()))
        }
        #[cfg(not(feature = "std"))]
        {
            Error::IO(value.to_string())
        }
    }
}

fn io_error(message: &'static str) -> Error {
    #[cfg(feature = "std")]
    {
        Error::IO(std::io::Error::other(message))
    }
    #[cfg(not(feature = "std"))]
    {
        Error::IO(alloc::string::String::from(message))
    }
}

pub(crate) fn read_file(path: &str) -> Result<Box<[u8]>> {
    let mut path_c = Vec::from(path.as_bytes());
    path_c.push(0);

    const O_RDONLY: usize = 0;
    const SEEK_END: usize = 2;
    const SEEK_SET: usize = 0;

    let fd = unsafe {
        #[cfg(any(
            target_arch = "aarch64",
            target_arch = "riscv64",
            target_arch = "riscv32"
        ))]
        {
            syscalls::syscall4(
                syscalls::Sysno::openat,
                -100isize as usize,
                path_c.as_ptr() as usize,
                O_RDONLY,
                0,
            )?
        }
        #[cfg(target_arch = "x86_64")]
        {
            syscalls::syscall2(syscalls::Sysno::open, path_c.as_ptr() as usize, O_RDONLY)?
        }
    };

    let read_result = (|| -> Result<Box<[u8]>> {
        let mut buffer = Vec::new();
        let file_size = unsafe {
            syscalls::syscall3(syscalls::Sysno::lseek, fd as usize, 0, SEEK_END).unwrap_or(0)
        };

        if file_size > 0
            && unsafe { syscalls::syscall3(syscalls::Sysno::lseek, fd as usize, 0, SEEK_SET) }
                .is_ok()
        {
            buffer.reserve_exact(file_size);
            unsafe {
                buffer.set_len(file_size);
            }
            let bytes_read = unsafe {
                syscalls::syscall3(
                    syscalls::Sysno::read,
                    fd as usize,
                    buffer.as_mut_ptr() as usize,
                    file_size,
                )?
            };
            if bytes_read != file_size {
                return Err(io_error("Failed to read complete file"));
            }
        } else {
            if file_size == 0 {
                let _ =
                    unsafe { syscalls::syscall3(syscalls::Sysno::lseek, fd as usize, 0, SEEK_SET) };
            }
            let mut temp = [0u8; 1024];
            loop {
                let bytes_read = unsafe {
                    syscalls::syscall3(
                        syscalls::Sysno::read,
                        fd as usize,
                        temp.as_mut_ptr() as usize,
                        temp.len(),
                    )?
                };
                if bytes_read == 0 {
                    break;
                }
                buffer.extend_from_slice(&temp[..bytes_read]);
            }
        }
        Ok(buffer.into_boxed_slice())
    })();

    unsafe {
        let _ = syscalls::syscall1(syscalls::Sysno::close, fd as usize);
    }
    read_result
}
