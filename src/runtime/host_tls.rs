//! TLS owned by the process's original dynamic loader.
use crate::{
    abi::{link_map::LinkMap, phdr::CDlPhdrInfo},
    library::{HostTlsRegistration, LoadedDylib},
};
use core::{
    ffi::{CStr, c_char, c_int, c_void},
    ptr::NonNull,
};
use elf_loader::{
    Result,
    arch::NativeArch,
    error::TlsError,
    relocation::RelocationArch,
    tls::{
        DefaultTlsResolver, TlsContext, TlsIndex, TlsInfo, TlsModuleId, TlsProvider, TlsTpOffset,
    },
};
use spin::Once;

type Open = unsafe extern "C" fn(*const c_char, c_int) -> *mut c_void;
type Close = unsafe extern "C" fn(*mut c_void) -> c_int;
type Info = unsafe extern "C" fn(*mut c_void, c_int, *mut c_void) -> c_int;
pub(super) type HostTlsFn = unsafe extern "C" fn(*const TlsIndex) -> *mut u8;

/// Original entry points, obtained from host ELF exports rather than interposable
/// calls to dlopen-rs's own dlopen/dlsym/dlclose implementations.
#[derive(Clone, Copy)]
pub(super) struct HostTlsOps {
    open: Open,
    close: Close,
    info: Option<Info>,
    get_addr: HostTlsFn,
    static_layout: bool,
}

pub(super) static HOST_TLS: Once<HostTlsOps> = Once::new();

impl HostTlsOps {
    pub(super) unsafe fn from_libc(lib: &LoadedDylib, get_addr: HostTlsFn) -> Option<Self> {
        let version = unsafe {
            lib.get::<unsafe extern "C" fn() -> *const c_char>("gnu_get_libc_version")
                .expect("host symbol lookup failed")
        }
        .map(|version| unsafe { CStr::from_ptr(version()) }.to_bytes());
        // The LinkMap adapter matches the x86_64 TLS fields in these versions.
        // Keep unknown layouts on public dynamic-TLS interfaces; metadata is
        // checked again before accepting a static offset below.
        let static_layout =
            cfg!(target_arch = "x86_64") && matches!(version, Some(b"2.39" | b"2.43"));
        Some(Self {
            open: *unsafe {
                lib.get::<Open>("dlopen")
                    .expect("host symbol lookup failed")
            }?,
            close: *unsafe {
                lib.get::<Close>("dlclose")
                    .expect("host symbol lookup failed")
            }?,
            info: if version.is_some() {
                Some(*unsafe {
                    lib.get::<Info>("dlinfo")
                        .expect("host symbol lookup failed")
                }?)
            } else {
                None
            },
            get_addr,
            static_layout,
        })
    }
}

struct HostTls {
    handle: usize,
    mod_id: TlsModuleId,
    ops: HostTlsOps,
}

impl Drop for HostTls {
    fn drop(&mut self) {
        unsafe { (self.ops.close)(self.handle as *mut c_void) };
    }
}

// The native reference pins this module and its loader. glibc owns all thread
// storage and accepts concurrent calls with the same handle/module ID.
unsafe impl TlsProvider for HostTls {
    unsafe fn get_or_init(&self, _context: &TlsContext) -> Result<NonNull<u8>> {
        let index = TlsIndex {
            ti_module: self.mod_id,
            ti_offset: 0usize.wrapping_sub(NativeArch::TLS_DTV_OFFSET),
        };
        NonNull::new(unsafe { (self.ops.get_addr)(&index) }).ok_or_else(|| {
            TlsError::InvalidModuleId {
                mod_id: self.mod_id,
            }
            .into()
        })
    }

    unsafe fn get(&self, _context: &TlsContext) -> Option<NonNull<u8>> {
        let info = self.ops.info?;
        let mut data: *mut u8 = core::ptr::null_mut();
        let status = unsafe {
            info(
                self.handle as *mut c_void,
                libc::RTLD_DI_TLS_DATA,
                (&mut data as *mut *mut u8).cast(),
            )
        };
        (status == 0).then(|| NonNull::new(data)).flatten()
    }
}

pub(super) unsafe fn import_host_tls(
    info: &CDlPhdrInfo,
    layout: TlsInfo,
) -> Result<HostTlsRegistration> {
    let ops = *HOST_TLS.get().ok_or(TlsError::ResolverUnsupported)?;
    let id = info.dlpi_tls_modid;
    if id == 0 {
        return Err(TlsError::ModuleMismatch.into());
    }
    let name = unsafe { CStr::from_ptr(info.dlpi_name) };
    let handle = unsafe {
        (ops.open)(
            if name.is_empty() {
                core::ptr::null()
            } else {
                name.as_ptr()
            },
            libc::RTLD_NOW | libc::RTLD_NOLOAD,
        )
    };
    if handle.is_null() {
        return Err(TlsError::ResolverUnsupported.into());
    }
    let provider = HostTls {
        handle: handle as usize,
        mod_id: TlsModuleId::new(id),
        ops,
    };
    if let Some(query) = ops.info {
        let mut queried_id = 0usize;
        if unsafe {
            query(
                handle,
                libc::RTLD_DI_TLS_MODID,
                (&mut queried_id as *mut usize).cast(),
            )
        } != 0
            || queried_id != id
        {
            return Err(TlsError::ModuleMismatch.into());
        }
    }

    let mut offset = None;
    if let Some(query) = ops.info.filter(|_| ops.static_layout) {
        let mut map: *mut LinkMap = core::ptr::null_mut();
        if unsafe {
            query(
                handle,
                libc::RTLD_DI_LINKMAP,
                (&mut map as *mut *mut LinkMap).cast(),
            )
        } == 0
        {
            if let Some(map) = unsafe { map.as_ref() } {
                // Verify the known layout against independently obtained metadata.
                // glibc x86_64 uses positive offsets below TP; 0/-1 are sentinels.
                if map.l_tls_modid == id
                    && map.l_tls_blocksize == layout.memsz
                    && map.l_tls_align == layout.align
                    && map.l_tls_offset > 0
                {
                    offset = Some(TlsTpOffset::new(-map.l_tls_offset));
                }
            }
        }
    }
    unsafe { DefaultTlsResolver::new().register_provider(layout, offset, provider) }
}
