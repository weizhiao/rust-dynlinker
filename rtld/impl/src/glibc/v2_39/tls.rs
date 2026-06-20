use alloc::alloc::{alloc_zeroed, dealloc, handle_alloc_error};
use core::{alloc::Layout, ptr};

const TCB_SELF_OFFSET: usize = 0x00;
const TCB_DTV_OFFSET: usize = 0x08;
const TCB_THREAD_SELF_OFFSET: usize = 0x10;
const TCB_STACK_GUARD_OFFSET: usize = 0x28;
const TCB_POINTER_GUARD_OFFSET: usize = 0x30;
const DTV_SLOT_COUNT: usize = 64;

const BOOTSTRAP_STACK_GUARD: usize = 0x2f6a_5d1b_3c4e_8790;
const BOOTSTRAP_POINTER_GUARD: usize = 0x6b43_1d29_84a0_7c5e;

#[derive(Clone, Copy)]
#[repr(C)]
struct DtvEntry {
    first: usize,
    second: usize,
}

pub(crate) unsafe fn init_tcb(tp: *mut u8) {
    unsafe { deallocate_tcb(tp) };
    let dtv = allocate_dtv();
    unsafe {
        ptr::write(tp.add(TCB_SELF_OFFSET) as *mut *mut u8, tp);
        ptr::write(tp.add(TCB_DTV_OFFSET) as *mut *mut DtvEntry, dtv);
        ptr::write(tp.add(TCB_THREAD_SELF_OFFSET) as *mut *mut u8, tp);
        ptr::write(
            tp.add(TCB_STACK_GUARD_OFFSET) as *mut usize,
            BOOTSTRAP_STACK_GUARD,
        );
        ptr::write(
            tp.add(TCB_POINTER_GUARD_OFFSET) as *mut usize,
            BOOTSTRAP_POINTER_GUARD,
        );
    }
}

pub(crate) unsafe fn dtv_value(tp: *mut u8, mod_id: usize) -> Option<*mut u8> {
    let entry = unsafe { dtv_entry(tp, mod_id)? };
    let value = unsafe { (*entry).first as *mut u8 };
    (!value.is_null()).then_some(value)
}

pub(crate) unsafe fn set_dtv_value(
    tp: *mut u8,
    mod_id: usize,
    value: *mut u8,
    to_free: *mut u8,
) -> bool {
    let Some(entry) = (unsafe { dtv_entry(tp, mod_id) }) else {
        return false;
    };
    unsafe {
        (*entry).first = value as usize;
        (*entry).second = to_free as usize;
    }
    true
}

pub(crate) unsafe fn deallocate_tcb(tp: *mut u8) {
    if tp.is_null() {
        return;
    }
    let dtv = unsafe { (tp.add(TCB_DTV_OFFSET) as *mut *mut DtvEntry).read() };
    if dtv.is_null() {
        return;
    }

    let base = unsafe { dtv.sub(1) };
    let slots = unsafe { (*base).first }.saturating_add(2);
    if let Ok(layout) = Layout::array::<DtvEntry>(slots) {
        unsafe { dealloc(base.cast(), layout) };
    }
    unsafe {
        ptr::write(
            tp.add(TCB_DTV_OFFSET) as *mut *mut DtvEntry,
            ptr::null_mut(),
        )
    };
}

fn allocate_dtv() -> *mut DtvEntry {
    let layout =
        Layout::array::<DtvEntry>(DTV_SLOT_COUNT + 2).expect("minimal DTV layout should be valid");
    let base = unsafe { alloc_zeroed(layout) as *mut DtvEntry };
    if base.is_null() {
        handle_alloc_error(layout);
    }
    unsafe {
        (*base).first = DTV_SLOT_COUNT;
        base.add(1)
    }
}

unsafe fn dtv_entry(tp: *mut u8, mod_id: usize) -> Option<*mut DtvEntry> {
    if tp.is_null() || mod_id == 0 {
        return None;
    }

    let dtv = unsafe { (tp.add(TCB_DTV_OFFSET) as *mut *mut DtvEntry).read() };
    if dtv.is_null() {
        return None;
    }

    let len = unsafe { (*dtv.sub(1)).first };
    if mod_id > len {
        return None;
    }

    Some(unsafe { dtv.add(mod_id) })
}
