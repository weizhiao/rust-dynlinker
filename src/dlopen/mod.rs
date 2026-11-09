mod observer;
mod run;

#[cfg(not(feature = "std"))]
pub(crate) use observer::DlopenObserver;
#[cfg(not(feature = "std"))]
pub(crate) use run::open_mapped;
pub(crate) use run::{LinkRoot, open, open_main};

/// Platform fallback directories, in resolver order, also exposed through dlinfo.
pub(crate) fn default_library_paths() -> &'static [&'static core::ffi::CStr] {
    &[
        #[cfg(target_arch = "x86_64")]
        c"/lib/x86_64-linux-gnu",
        #[cfg(target_arch = "x86_64")]
        c"/usr/lib/x86_64-linux-gnu",
        #[cfg(target_arch = "aarch64")]
        c"/lib/aarch64-linux-gnu",
        #[cfg(target_arch = "aarch64")]
        c"/usr/lib/aarch64-linux-gnu",
        #[cfg(target_arch = "riscv64")]
        c"/lib/riscv64-linux-gnu",
        #[cfg(target_arch = "riscv64")]
        c"/usr/lib/riscv64-linux-gnu",
        c"/lib",
        c"/usr/lib",
        c"/lib64",
        c"/usr/lib64",
    ]
}
