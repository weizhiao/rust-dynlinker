use crate::{ElfLibrary, core_impl::addr2dso};
use core::{
    ffi::{c_char, c_int, c_void},
    fmt::Debug,
    ptr::null,
};

#[repr(C)]
pub struct CDlinfo {
    pub dli_fname: *const c_char,
    pub dli_fbase: *mut c_void,
    pub dli_sname: *const c_char,
    pub dli_saddr: *mut c_void,
}

pub struct DlInfo {
    /// dylib
    dylib: ElfLibrary,
    /// Name of symbol whose definition overlaps addr
    sname: Option<&'static str>,
    /// Exact address of symbol named in dli_sname
    saddr: usize,
}

impl DlInfo {
    #[inline]
    pub fn dylib(&self) -> &ElfLibrary {
        &self.dylib
    }

    /// Name of symbol whose definition overlaps addr
    #[inline]
    pub fn symbol_name(&self) -> Option<&str> {
        self.sname
    }

    /// Exact address of symbol
    #[inline]
    pub fn symbol_addr(&self) -> Option<usize> {
        if self.saddr == 0 {
            None
        } else {
            Some(self.saddr)
        }
    }
}

impl Debug for DlInfo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DlInfo")
            .field("dylib", &self.dylib)
            .field("sname", &self.sname)
            .field("saddr", &format_args!("{:#x}", self.saddr))
            .finish()
    }
}

impl ElfLibrary {
    /// determines whether the address specified in addr is located in one of the shared objects loaded by the calling
    /// application.  If it is, then `dladdr` returns information about the shared object and
    /// symbol that overlaps addr.
    pub fn dladdr(addr: usize) -> Option<DlInfo> {
        log::info!(
            "dladdr: Try to find the symbol information corresponding to [{:#x}]",
            addr
        );
        addr2dso(addr).map(|dylib| {
            let (sname, saddr) = find_best_symbol(&dylib, addr).unwrap_or((None, 0));
            DlInfo {
                dylib,
                sname,
                saddr,
            }
        })
    }
}

fn find_best_symbol(dylib: &ElfLibrary, addr: usize) -> Option<(Option<&'static str>, usize)> {
    let base = dylib.base().get();
    let core = unsafe { dylib.inner.core_ref() };
    let exports = core.exports();
    let symbols = exports.symbols();
    let mut best_match = None;

    for sym in symbols {
        if sym.is_undef() || sym.st_value() == 0 || !sym.is_ok_bind() || !sym.is_ok_type() {
            continue;
        }

        let start = base + sym.st_value();
        let end = start + sym.st_size();
        if start <= addr && (sym.st_size() == 0 || addr < end) {
            if best_match.is_none_or(|(_, best_start)| start > best_start) {
                let name = exports
                    .symbol_name(sym)
                    .map(|name| unsafe { core::mem::transmute(name) });
                best_match = Some((name, start));
            }
        }
    }

    best_match
}

/// # Safety
/// It is the same as `dladdr`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dladdr(addr: *const c_void, info: *mut CDlinfo) -> c_int {
    if let Some(dl_info) = ElfLibrary::dladdr(addr as usize) {
        let info = unsafe { &mut *info };
        info.dli_fbase = dl_info.dylib().base().as_mut_ptr();
        info.dli_fname = dl_info.dylib().cname();
        info.dli_saddr = dl_info.symbol_addr().unwrap_or(0) as _;
        info.dli_sname = dl_info
            .sname
            .map_or(null(), |s| s.as_ptr() as *const c_char);
        1
    } else {
        0
    }
}
