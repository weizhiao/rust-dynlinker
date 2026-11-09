#[path = "support/dylib.rs"]
mod support;

use dlopen_rs::{ElfLibrary, OpenFlags, dlsym_default, dlsym_next};
use support::lib_path;

fn compile() {
    static ONCE: ::std::sync::Once = ::std::sync::Once::new();
    ONCE.call_once(|| support::build_dylibs(&["example_dylib"]));
}

#[unsafe(no_mangle)]
pub fn add(a: i32, b: i32) -> i32 {
    a + b + 100
}

#[test]
fn test_dlsym_next() {
    compile();
    let path = lib_path("libexample.so");
    let _lib = ElfLibrary::dlopen(path, OpenFlags::RTLD_GLOBAL | OpenFlags::RTLD_NOW).unwrap();

    // dlsym_next should skip the local "add" (which returns a+b+100)
    // and find the one in libexample.so (which returns a+b).
    let caller = add as *const () as usize;
    let add_func = unsafe { dlsym_next::<fn(i32, i32) -> i32>(caller, "add").unwrap() };

    // If it found the local one, it would be 103.
    // If it correctly found the next one, it should be 3.
    assert_eq!(add_func(1, 2), 3);

    // Verify it's not the same as local add
    assert_ne!(add_func.into_raw() as usize, add as *const () as usize);

    // Test non-existent symbol
    let non_existent = unsafe { dlsym_next::<fn()>(caller, "non_existent_symbol") };
    assert!(non_existent.is_err());
}

#[test]
fn test_dlsym_default() {
    compile();
    let path = lib_path("libexample.so");
    // Must be RTLD_GLOBAL to be found by dlsym_default
    let _lib = ElfLibrary::dlopen(path, OpenFlags::RTLD_GLOBAL | OpenFlags::RTLD_NOW).unwrap();

    let add = dlsym_default::<fn(i32, i32) -> i32>("add").unwrap();
    assert_eq!(add(10, 20), 30);
}

#[test]
fn test_dlsym() {
    compile();
    let path = lib_path("libexample.so");
    let lib = ElfLibrary::dlopen(path, OpenFlags::RTLD_GLOBAL).unwrap();
    let print = unsafe { lib.get::<fn(&str)>("print").unwrap() };
    print("dlopen-rs: hello world");
}
