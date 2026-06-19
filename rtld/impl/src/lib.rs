#![no_std]

extern crate alloc;

mod arch;
mod bootstrap;
mod cli;
mod glibc;
mod globals;
mod memory;
mod runtime;
mod symbols;
mod tls;
#[cfg(all(target_arch = "x86_64", target_os = "linux", target_env = ""))]
mod versions;

#[doc(hidden)]
pub fn force_link() {}
