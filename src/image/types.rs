use alloc::{boxed::Box, ffi::CString, string::String, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use elf_loader::{elf::ElfDyn, memory::VmAddr};
use spin::Once;

use crate::abi::link_map::LinkMap;

const UNLOADING: usize = 1 << (usize::BITS - 1);

#[derive(Default)]
pub(crate) struct ModuleState {
    tls_dtors: AtomicUsize,
}

impl ModuleState {
    #[cfg(feature = "std")]
    pub(crate) fn register_tls_dtor(&self) -> bool {
        self.tls_dtors
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |state| {
                if state & UNLOADING != 0 || state == UNLOADING - 1 {
                    None
                } else {
                    Some(state + 1)
                }
            })
            .is_ok()
    }

    #[cfg(feature = "std")]
    pub(crate) fn unregister_tls_dtor(&self) {
        let previous = self.tls_dtors.fetch_sub(1, Ordering::Release);
        debug_assert!(
            previous > 0 && previous & UNLOADING == 0,
            "TLS destructor count must have a matching registration"
        );
    }

    #[inline]
    pub(crate) fn has_tls_dtors(&self) -> bool {
        self.tls_dtors.load(Ordering::Acquire) != 0
    }

    pub(crate) fn begin_unload(&self) -> bool {
        self.tls_dtors
            .compare_exchange(0, UNLOADING, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    pub(crate) fn cancel_unload(&self) {
        let result =
            self.tls_dtors
                .compare_exchange(UNLOADING, 0, Ordering::Release, Ordering::Relaxed);
        debug_assert!(result.is_ok(), "only a planned unload can be cancelled");
    }
}

#[derive(Default)]
pub struct ExtraData {
    pub(crate) c_name: Option<CString>,
    pub(crate) link_map: Option<Box<LinkMap>>,
    pub(crate) needed_libs: Vec<String>,
    pub(crate) dynamic_table: Option<Box<[ElfDyn]>>,
    pub(crate) fini: Once<Box<[VmAddr]>>,
    pub(crate) fini_ran: Arc<AtomicBool>,
    pub(crate) state: Arc<ModuleState>,
}

impl core::fmt::Debug for ExtraData {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut d = f.debug_struct("UserData");
        d.field("c_name", &self.c_name);
        d.field("link_map", &self.link_map);
        d.field("needed_libs", &self.needed_libs);
        d.field("dynamic_table", &self.dynamic_table);
        d.field("fini", &self.fini.get());
        d.finish()
    }
}
