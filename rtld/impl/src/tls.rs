use alloc::{
    alloc::{alloc_zeroed, dealloc, handle_alloc_error},
    vec::Vec,
};
use core::{alloc::Layout, ffi::c_void, ptr};
use dlopen_rs::rtld::{
    self, DefaultTlsResolver, ElfResult, RtldTlsOps, TlsError, TlsIndex, TlsInfo, TlsModuleId,
    TlsResolver, TlsTpOffset,
};
use spin::Mutex;

const STATIC_TLS_ARENA_SIZE: usize = 1024 * 1024;
const TLS_TCB_SIZE: usize = 4096;
const TLS_TCB_ALIGN: usize = 64;

pub(crate) fn install_resolver_ops() {
    rtld::register_tls_ops(RtldTlsOps {
        register_static: register_static_module,
        refresh_static_tls,
    });
}

pub(crate) extern "C" fn get_addr(index: *const usize) -> *mut c_void {
    <DefaultTlsResolver as TlsResolver>::tls_get_addr(index.cast::<TlsIndex>()).cast()
}

pub(crate) fn static_info() -> (usize, usize) {
    let (used, align) = static_used_info();
    let align = align.max(TLS_TCB_ALIGN).max(1);
    let size = align_up(used, align)
        .and_then(|used| used.checked_add(TLS_TCB_SIZE))
        .unwrap_or(0);
    (size, align)
}

fn static_used_info() -> (usize, usize) {
    let static_tls = STATIC_TLS.lock();
    static_tls
        .as_ref()
        .map(|area| (area.used, area.max_align))
        .unwrap_or((0, 1))
}

struct StaticTlsArea {
    tp: *mut u8,
    used: usize,
    max_align: usize,
}

unsafe impl Send for StaticTlsArea {}
unsafe impl Sync for StaticTlsArea {}

static STATIC_TLS: Mutex<Option<StaticTlsArea>> = Mutex::new(None);

#[derive(Clone)]
struct StaticTlsModule {
    info: TlsInfo,
    offset: TlsTpOffset,
}

static STATIC_TLS_MODULES: Mutex<Vec<StaticTlsModule>> = Mutex::new(Vec::new());

struct TlsAllocation {
    tp: *mut u8,
    base: *mut u8,
    layout: Layout,
}

unsafe impl Send for TlsAllocation {}
unsafe impl Sync for TlsAllocation {}

static TLS_ALLOCATIONS: Mutex<Vec<TlsAllocation>> = Mutex::new(Vec::new());

fn register_static_module(tls_info: &TlsInfo) -> ElfResult<(TlsModuleId, TlsTpOffset)> {
    let mut static_tls = STATIC_TLS.lock();
    if static_tls.is_none() {
        *static_tls = Some(ensure_static_tls_area()?);
    }
    let area = static_tls
        .as_mut()
        .expect("rtld static TLS area should be initialized");
    let align = tls_info
        .align
        .max(1)
        .checked_next_power_of_two()
        .ok_or(TlsError::StaticResolverUnsupported)?;

    let used = align_up(
        area.used
            .checked_add(tls_info.memsz)
            .ok_or(TlsError::StaticResolverUnsupported)?,
        align,
    )
    .ok_or(TlsError::StaticResolverUnsupported)?;
    if used > STATIC_TLS_ARENA_SIZE {
        return Err(TlsError::StaticResolverUnsupported.into());
    }

    let offset = TlsTpOffset::new(-(used as isize));
    let module = StaticTlsModule {
        info: tls_info.clone(),
        offset,
    };
    unsafe { init_static_tls_module(area.tp, &module) };

    area.used = used;
    area.max_align = area.max_align.max(align);
    let id = <DefaultTlsResolver as TlsResolver>::add_static_tls(tls_info, offset)?;
    STATIC_TLS_MODULES.lock().push(module);
    Ok((id, offset))
}

pub(crate) unsafe fn refresh_static_tls() {
    let Some(tp) = STATIC_TLS.lock().as_ref().map(|area| area.tp) else {
        return;
    };
    for module in STATIC_TLS_MODULES.lock().iter() {
        unsafe { init_static_tls_module(tp, module) };
    }
}

fn ensure_static_tls_area() -> ElfResult<StaticTlsArea> {
    let layout = Layout::from_size_align(STATIC_TLS_ARENA_SIZE + TLS_TCB_SIZE, 4096)
        .map_err(|_| TlsError::StaticResolverUnsupported)?;
    let base = unsafe { alloc_zeroed(layout) };
    if base.is_null() {
        handle_alloc_error(layout);
    }

    let tp = unsafe { base.add(STATIC_TLS_ARENA_SIZE) };
    init_tcb(tp)?;
    install_thread_pointer(tp)?;

    Ok(StaticTlsArea {
        tp,
        used: 0,
        max_align: 1,
    })
}

#[inline]
fn align_up(value: usize, align: usize) -> Option<usize> {
    value
        .checked_add(align - 1)
        .map(|value| value & !(align - 1))
}

fn init_tcb(tp: *mut u8) -> ElfResult<()> {
    if tp.is_null() {
        return Err(TlsError::StaticResolverUnsupported.into());
    }
    unsafe { crate::glibc::init_tcb(tp) };
    Ok(())
}

fn install_thread_pointer(tp: *mut u8) -> ElfResult<()> {
    if tp.is_null() || !crate::arch::install_thread_pointer(tp) {
        return Err(TlsError::StaticResolverUnsupported.into());
    }
    Ok(())
}

pub(crate) unsafe fn allocate(storage: *mut c_void) -> *mut c_void {
    let storage = if storage.is_null() {
        let Some(storage) = allocate_storage() else {
            return ptr::null_mut();
        };
        storage
    } else {
        storage.cast()
    };

    unsafe { init(storage.cast()).cast() }
}

pub(crate) unsafe fn init(storage: *mut c_void) -> *mut c_void {
    let storage = storage.cast::<u8>();
    if storage.is_null() || init_tcb(storage).is_err() {
        return ptr::null_mut();
    }

    for module in STATIC_TLS_MODULES.lock().iter() {
        unsafe { init_static_tls_module(storage, module) };
    }

    storage.cast()
}

pub(crate) unsafe fn deallocate(storage: *mut c_void, dealloc_tcb: bool) {
    if !dealloc_tcb || storage.is_null() {
        return;
    }

    let mut allocations = TLS_ALLOCATIONS.lock();
    let Some(index) = allocations
        .iter()
        .position(|allocation| allocation.tp == storage.cast())
    else {
        return;
    };
    let allocation = allocations.swap_remove(index);
    unsafe { dealloc(allocation.base, allocation.layout) };
}

fn allocate_storage() -> Option<*mut u8> {
    let (static_size, static_align) = static_used_info();
    let align = static_align
        .max(TLS_TCB_ALIGN)
        .max(core::mem::align_of::<usize>())
        .checked_next_power_of_two()?;
    let static_size = align_up(static_size, align)?;
    let total_size = static_size.checked_add(TLS_TCB_SIZE)?;
    let layout = Layout::from_size_align(total_size.max(1), align).ok()?;
    let base = unsafe { alloc_zeroed(layout) };
    if base.is_null() {
        handle_alloc_error(layout);
    }

    let tp = unsafe { base.add(static_size) };
    TLS_ALLOCATIONS
        .lock()
        .push(TlsAllocation { tp, base, layout });
    Some(tp)
}

unsafe fn init_static_tls_module(tp: *mut u8, module: &StaticTlsModule) {
    let dst = unsafe { tp.offset(module.offset.get()) };
    unsafe {
        ptr::copy_nonoverlapping(module.info.image().as_ptr(), dst, module.info.filesz);
        ptr::write_bytes(
            dst.add(module.info.filesz),
            0,
            module.info.memsz - module.info.filesz,
        );
    }
}
