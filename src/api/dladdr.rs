use crate::{ElfLibrary, abi::dladdr::CDlInfo, registry::library_by_addr};
use core::{
    ffi::{c_char, c_int, c_void},
    fmt::Debug,
    ptr::null,
};

pub struct DlInfo {
    dylib: ElfLibrary,
    sname: Option<&'static str>,
    saddr: usize,
}

impl DlInfo {
    #[inline]
    pub fn dylib(&self) -> &ElfLibrary {
        &self.dylib
    }

    #[inline]
    pub fn symbol_name(&self) -> Option<&str> {
        self.sname
    }

    #[inline]
    pub fn symbol_addr(&self) -> Option<usize> {
        (self.saddr != 0).then_some(self.saddr)
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
    pub fn dladdr(addr: usize) -> Option<DlInfo> {
        log::info!(
            "dladdr: Try to find the symbol information corresponding to [{:#x}]",
            addr
        );
        library_by_addr(addr).map(|dylib| {
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
    let mut best_match = None;

    for symbol in exports.symbols() {
        if symbol.is_undef()
            || symbol.st_value() == 0
            || !symbol.is_ok_bind()
            || !symbol.is_ok_type()
        {
            continue;
        }
        let start = base + symbol.st_value();
        let end = start + symbol.st_size();
        if start <= addr
            && (symbol.st_size() == 0 || addr < end)
            && best_match.is_none_or(|(_, best_start)| start > best_start)
        {
            let name = exports
                .symbol_name(symbol)
                .map(|name| unsafe { core::mem::transmute(name) });
            best_match = Some((name, start));
        }
    }
    best_match
}

pub(crate) unsafe fn dladdr_raw(addr: *const c_void, info: *mut CDlInfo) -> c_int {
    let Some(dl_info) = ElfLibrary::dladdr(addr as usize) else {
        return 0;
    };
    let info = unsafe { &mut *info };
    info.dli_fbase = dl_info.dylib().base().as_mut_ptr();
    info.dli_fname = dl_info.dylib().cname();
    info.dli_saddr = dl_info.symbol_addr().unwrap_or(0) as _;
    info.dli_sname = dl_info
        .symbol_name()
        .map_or(null(), |name| name.as_ptr() as *const c_char);
    1
}

/// # Safety
/// It is the same as `dladdr`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dladdr(addr: *const c_void, info: *mut CDlInfo) -> c_int {
    unsafe { dladdr_raw(addr, info) }
}
