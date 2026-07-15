pub(crate) mod debug;

pub(crate) static mut ARGC: usize = 0;
pub(crate) static mut ARGV: *const *mut core::ffi::c_char = core::ptr::null();
pub(crate) static mut ENVP: *const *const core::ffi::c_char = core::ptr::null();

#[cfg(feature = "std")]
mod host;
#[cfg(not(feature = "std"))]
pub mod rtld;
