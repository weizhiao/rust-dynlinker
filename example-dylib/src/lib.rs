//!An example dynamically loadable library.
//!
//! This crate creates a dynamic library that can be used for testing purposes.

use std::{
    backtrace::Backtrace,
    cell::Cell,
    ffi::{c_char, c_int, c_void, CStr, CString},
    os::unix::ffi::OsStrExt,
    path::PathBuf,
    sync::atomic::{AtomicPtr, AtomicUsize, Ordering},
    thread,
};

#[no_mangle]
pub fn panic() {
    let res = std::panic::catch_unwind(|| {
        panic!("panic!");
    });
    assert!(res.is_err());
    println!("catch panic!")
}

thread_local! {
    static NUM:Cell<i32>=Cell::new(0)
}

unsafe extern "C" {
    static __dso_handle: c_void;
    fn __cxa_thread_atexit_impl(
        func: unsafe extern "C" fn(*mut c_void),
        arg: *mut c_void,
        dso_handle: *mut c_void,
    ) -> i32;
    fn pthread_create(
        thread: *mut usize,
        attr: *const c_void,
        start: unsafe extern "C" fn(*mut c_void) -> *mut c_void,
        arg: *mut c_void,
    ) -> i32;
    fn pthread_detach(thread: usize) -> i32;
    fn dladdr(addr: *const c_void, info: *mut DlInfo) -> c_int;
    fn dlopen(path: *const c_char, flags: c_int) -> *mut c_void;
    fn dlclose(handle: *mut c_void) -> c_int;
}

#[repr(C)]
struct DlInfo {
    dli_fname: *const c_char,
    dli_fbase: *mut c_void,
    dli_sname: *const c_char,
    dli_saddr: *mut c_void,
}

static NESTED_INIT_HANDLE: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

#[used]
#[unsafe(link_section = ".init_array")]
static NESTED_INIT: unsafe extern "C" fn() = nested_init;

unsafe extern "C" fn nested_init() {
    let mut info = DlInfo {
        dli_fname: std::ptr::null(),
        dli_fbase: std::ptr::null_mut(),
        dli_sname: std::ptr::null(),
        dli_saddr: std::ptr::null_mut(),
    };
    if unsafe { dladdr(nested_init as *const c_void, &mut info) } == 0 || info.dli_fname.is_null() {
        return;
    }

    let current = PathBuf::from(std::ffi::OsStr::from_bytes(unsafe {
        CStr::from_ptr(info.dli_fname).to_bytes()
    }));
    if current.file_name().and_then(|name| name.to_str()) != Some("libnested_outer.so") {
        return;
    }

    let target = current.with_file_name("libpromotion.so");
    let Ok(target) = CString::new(target.as_os_str().as_bytes()) else {
        return;
    };
    let handle = unsafe { dlopen(target.as_ptr(), 2) };
    NESTED_INIT_HANDLE.store(handle, Ordering::Release);
}

#[no_mangle]
pub extern "C" fn nested_init_loaded() -> bool {
    !NESTED_INIT_HANDLE.load(Ordering::Acquire).is_null()
}

#[no_mangle]
pub unsafe extern "C" fn close_nested_init_handle() {
    let handle = NESTED_INIT_HANDLE.swap(std::ptr::null_mut(), Ordering::AcqRel);
    if !handle.is_null() {
        unsafe { dlclose(handle) };
    }
}

unsafe extern "C" fn notify_tls_drop(arg: *mut c_void) {
    let state = unsafe { &*(arg as *const AtomicUsize) };
    state.store(3, Ordering::Release);
}

unsafe extern "C" fn tls_worker(arg: *mut c_void) -> *mut c_void {
    let state = unsafe { &*(arg as *const AtomicUsize) };
    let result = unsafe {
        __cxa_thread_atexit_impl(notify_tls_drop, arg, &__dso_handle as *const _ as *mut _)
    };
    if result != 0 {
        state.store(4, Ordering::Release);
        return std::ptr::null_mut();
    }

    state.store(1, Ordering::Release);
    while state.load(Ordering::Acquire) != 2 {
        thread::yield_now();
    }
    std::ptr::null_mut()
}

#[no_mangle]
pub fn backtrace() {
    println!("{}", Backtrace::force_capture());
}

#[no_mangle]
pub fn thread_local() {
    println!("{}", HELLO);
    let handle = thread::spawn(|| {
        NUM.set(NUM.get() + 1);
        println!("thread1:{}", NUM.get());
    });
    handle.join().unwrap();
    NUM.set(NUM.get() + 2);
    println!("thread2:{}", NUM.get());
}

#[no_mangle]
pub unsafe extern "C" fn start_tls_destructor_thread(state: *const AtomicUsize) {
    let mut thread = 0;
    let result = unsafe {
        pthread_create(
            &mut thread,
            std::ptr::null(),
            tls_worker,
            state as *mut c_void,
        )
    };
    if result == 0 {
        unsafe { pthread_detach(thread) };
    } else {
        unsafe { &*state }.store(4, Ordering::Release);
    }
}

#[no_mangle]
pub fn print(str: &str) {
    println!("{}", str);
}

#[no_mangle]
pub fn add(a: i32, b: i32) -> i32 {
    a + b
}

#[no_mangle]
fn args() {
    let args = std::env::args();
    println!("{:?}", args);
}

#[no_mangle]
pub static HELLO: &str = "Hello!";
