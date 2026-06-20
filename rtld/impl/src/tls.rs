use alloc::{
    alloc::{alloc_zeroed, dealloc, handle_alloc_error},
    vec::Vec,
};
use core::{alloc::Layout, ffi::c_void, ptr};
use dlopen_rs::rtld::{
    self, ElfResult, RtldTlsOps, TlsError, TlsImageSource, TlsIndex, TlsInfo, TlsModuleId,
    TlsTemplate, TlsTpOffset,
};
use spin::Mutex;

const STATIC_TLS_ARENA_SIZE: usize = 1024 * 1024;
const TLS_TCB_SIZE: usize = 2368;
const TLS_TCB_ALIGN: usize = 64;
const RSEQ_AREA_SIZE: usize = 32;
const RSEQ_AREA_ALIGN: usize = 32;
const RSEQ_CPU_ID_OFFSET: usize = 4;
const RSEQ_CPU_ID_REGISTRATION_FAILED: u32 = (-2i32) as u32;

pub(crate) fn install_resolver_ops() {
    rtld::register_tls_ops(RtldTlsOps {
        register: register_dynamic_module,
        register_static: register_static_module,
        add_static_tls: add_static_module,
        init_tls: init_tls_module,
        unregister: unregister_module,
        tls_get_addr: get_addr,
        tls_get_addr_soft: get_addr_soft,
    });
}

pub(crate) extern "C" fn get_addr(index: *const TlsIndex) -> *mut u8 {
    let Some(index) = (unsafe { index.as_ref() }) else {
        return ptr::null_mut();
    };
    let Some(module) = tls_module(index.ti_module) else {
        return ptr::null_mut();
    };

    match module {
        TlsModule::Static { offset, .. } => static_tls_addr(offset, index.ti_offset),
        TlsModule::Dynamic { info, source } => {
            dynamic_tls_addr(index.ti_module, &info, source.as_ref(), index.ti_offset)
        }
    }
}

pub(crate) fn get_addr_soft(mod_id: TlsModuleId) -> *mut u8 {
    let tp = crate::arch::get_thread_pointer();
    if tp.is_null() {
        return ptr::null_mut();
    }
    unsafe { crate::glibc::dtv_value(tp, mod_id.get()) }.unwrap_or(ptr::null_mut())
}

pub(crate) fn static_info() -> (usize, usize) {
    let (used, align) = static_layout_info();
    let size = align_up(used, align)
        .and_then(|used| used.checked_add(TLS_TCB_SIZE))
        .unwrap_or(0);
    (size, align)
}

pub(crate) fn rseq_offset() -> isize {
    static_rseq_offset(static_used_info().0).unwrap_or(0)
}

fn static_used_info() -> (usize, usize) {
    let static_tls = STATIC_TLS.lock();
    static_tls
        .as_ref()
        .map(|area| (area.used, area.max_align))
        .unwrap_or((0, 1))
}

fn static_layout_info() -> (usize, usize) {
    let (used, align) = static_used_info();
    let used = static_used_with_rseq(used).unwrap_or(0);
    let align = align.max(RSEQ_AREA_ALIGN).max(TLS_TCB_ALIGN).max(1);
    (used, align)
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
    id: TlsModuleId,
    info: TlsInfo,
    source: Option<TlsImageSource>,
    offset: TlsTpOffset,
}

static STATIC_TLS_MODULES: Mutex<Vec<StaticTlsModule>> = Mutex::new(Vec::new());

#[derive(Clone)]
enum TlsModule {
    Dynamic {
        info: TlsInfo,
        source: Option<TlsImageSource>,
    },
    Static {
        offset: TlsTpOffset,
    },
}

static TLS_MODULES: Mutex<Vec<Option<TlsModule>>> = Mutex::new(Vec::new());

struct DynamicTlsBlock {
    tp: *mut u8,
    ptr: *mut u8,
    layout: Layout,
}

unsafe impl Send for DynamicTlsBlock {}
unsafe impl Sync for DynamicTlsBlock {}

static DYNAMIC_TLS_BLOCKS: Mutex<Vec<DynamicTlsBlock>> = Mutex::new(Vec::new());

struct TlsAllocation {
    tp: *mut u8,
    base: *mut u8,
    layout: Layout,
}

unsafe impl Send for TlsAllocation {}
unsafe impl Sync for TlsAllocation {}

static TLS_ALLOCATIONS: Mutex<Vec<TlsAllocation>> = Mutex::new(Vec::new());

fn register_dynamic_module(tls_info: &TlsInfo) -> ElfResult<TlsModuleId> {
    register_module(TlsModule::Dynamic {
        info: *tls_info,
        source: None,
    })
}

fn register_module(module: TlsModule) -> ElfResult<TlsModuleId> {
    let mut modules = TLS_MODULES.lock();
    let raw = modules
        .len()
        .checked_add(1)
        .ok_or(TlsError::ResolverUnsupported)?;
    modules.push(Some(module));
    Ok(TlsModuleId::new(raw))
}

fn tls_module(id: TlsModuleId) -> Option<TlsModule> {
    let raw = id.get();
    if raw == 0 {
        return None;
    }
    TLS_MODULES
        .lock()
        .get(raw - 1)
        .and_then(|slot| slot.clone())
}

fn unregister_module(id: TlsModuleId) {
    let raw = id.get();
    if raw == 0 {
        return;
    }

    if let Some(slot) = TLS_MODULES.lock().get_mut(raw - 1) {
        *slot = None;
    }
    STATIC_TLS_MODULES.lock().retain(|module| module.id != id);
}

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

    let used = static_module_end(area.used, tls_info.memsz, tls_info.vaddr, align)
        .ok_or(TlsError::StaticResolverUnsupported)?;
    if static_used_with_rseq(used).ok_or(TlsError::StaticResolverUnsupported)?
        > STATIC_TLS_ARENA_SIZE
    {
        return Err(TlsError::StaticResolverUnsupported.into());
    }

    let offset = TlsTpOffset::new(-(used as isize));
    let id = register_module(TlsModule::Static { offset })?;
    area.used = used;
    area.max_align = area.max_align.max(align);
    STATIC_TLS_MODULES.lock().push(StaticTlsModule {
        id,
        info: *tls_info,
        source: None,
        offset,
    });
    Ok((id, offset))
}

fn add_static_module(tls_info: &TlsInfo, offset: TlsTpOffset) -> ElfResult<TlsModuleId> {
    let id = register_module(TlsModule::Static { offset })?;
    STATIC_TLS_MODULES.lock().push(StaticTlsModule {
        id,
        info: *tls_info,
        source: None,
        offset,
    });
    Ok(id)
}

fn init_tls_module(
    source: TlsImageSource,
    id: TlsModuleId,
    offset: Option<TlsTpOffset>,
) -> ElfResult<()> {
    let info = source.info();
    match offset {
        Some(offset) => init_static_tls(info, source, id, offset),
        None => init_dynamic_tls(info, source, id),
    }
}

fn init_dynamic_tls(info: TlsInfo, source: TlsImageSource, id: TlsModuleId) -> ElfResult<()> {
    let raw = id.get();
    if raw == 0 {
        return Err(TlsError::ResolverUnsupported.into());
    }

    let mut modules = TLS_MODULES.lock();
    let Some(slot) = modules.get_mut(raw - 1) else {
        return Err(TlsError::ResolverUnsupported.into());
    };
    *slot = Some(TlsModule::Dynamic {
        info,
        source: Some(source),
    });
    Ok(())
}

fn init_static_tls(
    info: TlsInfo,
    source: TlsImageSource,
    id: TlsModuleId,
    offset: TlsTpOffset,
) -> ElfResult<()> {
    update_static_module_slot(id, offset)?;
    let module = {
        let mut modules = STATIC_TLS_MODULES.lock();
        if let Some(module) = modules.iter_mut().find(|module| module.id == id) {
            module.info = info;
            module.source = Some(source);
            module.offset = offset;
            module.clone()
        } else {
            let module = StaticTlsModule {
                id,
                info,
                source: Some(source),
                offset,
            };
            modules.push(module.clone());
            module
        }
    };

    if let Some((tp, used)) = STATIC_TLS.lock().as_ref().map(|area| (area.tp, area.used)) {
        unsafe {
            init_static_tls_module(tp, &module);
            init_rseq_area(tp, used);
        }
    }
    Ok(())
}

fn update_static_module_slot(id: TlsModuleId, offset: TlsTpOffset) -> ElfResult<()> {
    let raw = id.get();
    if raw == 0 {
        return Err(TlsError::StaticResolverUnsupported.into());
    }

    let mut modules = TLS_MODULES.lock();
    let Some(slot) = modules.get_mut(raw - 1) else {
        return Err(TlsError::StaticResolverUnsupported.into());
    };
    *slot = Some(TlsModule::Static { offset });
    Ok(())
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

fn static_module_end(used: usize, memsz: usize, vaddr: usize, align: usize) -> Option<usize> {
    let firstbyte = (0usize.wrapping_sub(vaddr)) & (align - 1);
    let min_end = used.checked_add(memsz)?;
    let aligned = align_up(min_end.saturating_sub(firstbyte), align)?;
    let end = aligned.checked_add(firstbyte)?;
    if end < min_end {
        end.checked_add(align)
    } else {
        Some(end)
    }
}

fn static_used_with_rseq(used: usize) -> Option<usize> {
    align_up(used, RSEQ_AREA_ALIGN)?.checked_add(RSEQ_AREA_SIZE)
}

fn static_rseq_offset(used: usize) -> Option<isize> {
    let offset = static_used_with_rseq(used)?;
    isize::try_from(offset).ok().map(|offset| -offset)
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

fn static_tls_addr(offset: TlsTpOffset, ti_offset: usize) -> *mut u8 {
    let tp = crate::arch::get_thread_pointer();
    if tp.is_null() {
        return ptr::null_mut();
    }
    unsafe { tp.offset(offset.get()).add(ti_offset) }
}

fn dynamic_tls_addr(
    id: TlsModuleId,
    info: &TlsInfo,
    source: Option<&TlsImageSource>,
    ti_offset: usize,
) -> *mut u8 {
    let tp = crate::arch::get_thread_pointer();
    if tp.is_null() {
        return ptr::null_mut();
    }

    if let Some(ptr) = unsafe { crate::glibc::dtv_value(tp, id.get()) } {
        return unsafe { ptr.add(ti_offset) };
    }

    let Some(ptr) = allocate_dynamic_block(tp, id, info, source) else {
        return ptr::null_mut();
    };
    unsafe { ptr.add(ti_offset) }
}

fn allocate_dynamic_block(
    tp: *mut u8,
    id: TlsModuleId,
    info: &TlsInfo,
    source: Option<&TlsImageSource>,
) -> Option<*mut u8> {
    let align = info.align.max(1).checked_next_power_of_two().unwrap_or(1);
    let layout = Layout::from_size_align(info.memsz.max(1), align).ok()?;
    let ptr = unsafe { alloc_zeroed(layout) };
    if ptr.is_null() {
        handle_alloc_error(layout);
    }

    let source = source?;
    let mut init = |tls: TlsTemplate<'_>| {
        let image = tls.image;
        unsafe {
            ptr::copy_nonoverlapping(image.as_ptr(), ptr, image.len());
            ptr::write_bytes(ptr.add(image.len()), 0, info.memsz - image.len());
        }
        Ok(())
    };
    if source.with_template(&mut init).is_err() {
        unsafe { dealloc(ptr, layout) };
        return None;
    }
    if !unsafe { crate::glibc::set_dtv_value(tp, id.get(), ptr, ptr) } {
        unsafe { dealloc(ptr, layout) };
        return None;
    }

    DYNAMIC_TLS_BLOCKS
        .lock()
        .push(DynamicTlsBlock { tp, ptr, layout });
    Some(ptr)
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
    unsafe { init_rseq_area(storage, static_used_info().0) };

    storage.cast()
}

pub(crate) unsafe fn deallocate(storage: *mut c_void, dealloc_tcb: bool) {
    if storage.is_null() {
        return;
    }

    free_dynamic_blocks(storage.cast());
    if !dealloc_tcb {
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

fn free_dynamic_blocks(tp: *mut u8) {
    let mut blocks = DYNAMIC_TLS_BLOCKS.lock();
    let mut index = 0;
    while index < blocks.len() {
        if blocks[index].tp == tp {
            let block = blocks.swap_remove(index);
            unsafe { dealloc(block.ptr, block.layout) };
        } else {
            index += 1;
        }
    }
}

fn allocate_storage() -> Option<*mut u8> {
    let (static_size, static_align) = static_used_info();
    let static_size = static_used_with_rseq(static_size)?;
    let static_align = static_align.max(RSEQ_AREA_ALIGN);
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
    let Some(source) = module.source.as_ref() else {
        return;
    };
    let mut init = |tls: TlsTemplate<'_>| {
        let image = tls.image;
        unsafe {
            ptr::copy_nonoverlapping(image.as_ptr(), dst, image.len());
            ptr::write_bytes(dst.add(image.len()), 0, module.info.memsz - image.len());
        }
        Ok(())
    };
    if source.with_template(&mut init).is_err() {
        return;
    };
    unsafe { crate::glibc::set_dtv_value(tp, module.id.get(), dst, ptr::null_mut()) };
}

unsafe fn init_rseq_area(tp: *mut u8, used: usize) {
    let Some(offset) = static_rseq_offset(used) else {
        return;
    };
    let area = unsafe { tp.offset(offset) };
    unsafe {
        ptr::write_bytes(area, 0, RSEQ_AREA_SIZE);
        ptr::write(
            area.add(RSEQ_CPU_ID_OFFSET).cast::<u32>(),
            RSEQ_CPU_ID_REGISTRATION_FAILED,
        );
    }
}
