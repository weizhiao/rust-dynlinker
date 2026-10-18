#![cfg(all(unix, feature = "std"))]

use dlopen_rs::{ElfLibrary, OpenFlags, api};
use std::{
    ffi::{CStr, CString, OsStr},
    os::unix::ffi::OsStrExt,
    process::Command,
};

#[test]
fn non_utf8_paths_preserve_identity_and_c_names() {
    let dir = std::env::temp_dir().join(format!("dlopen-non-utf8-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let source = dir.join("fixture.c");
    std::fs::write(&source, "int non_utf8_answer(void) { return 42; }\n").unwrap();
    let path = dir.join(OsStr::from_bytes(b"lib\xff.so"));
    assert!(
        Command::new("cc")
            .args(["-shared", "-fPIC", "-nostdlib"])
            .arg(&source)
            .arg("-o")
            .arg(&path)
            .status()
            .unwrap()
            .success()
    );
    let filename = CString::new(path.as_os_str().as_bytes()).unwrap();
    unsafe {
        // Start with the C entry point, so it must actually open the raw path.
        let handle = api::dlopen(filename.as_ptr(), OpenFlags::RTLD_NOW.bits() as _);
        assert!(!handle.is_null());
        let symbol = api::dlsym(handle, c"non_utf8_answer".as_ptr());
        assert!(!symbol.is_null());
        let answer: unsafe extern "C" fn() -> i32 = std::mem::transmute(symbol);
        assert_eq!(answer(), 42);

        let library = ElfLibrary::dlopen(&path, OpenFlags::RTLD_NOLOAD).unwrap();
        assert_eq!(library.name(), b"lib\xff.so");
        assert_eq!(CStr::from_ptr(library.cname()), filename.as_c_str());
        let via_os_str = ElfLibrary::dlopen(path.as_os_str(), OpenFlags::RTLD_NOLOAD).unwrap();
        assert_eq!(via_os_str.base(), library.base());

        // Distinct invalid bytes must not collapse to the same replacement character.
        let other = dir.join(OsStr::from_bytes(b"lib\xfe.so"));
        assert!(ElfLibrary::dlopen(&other, OpenFlags::RTLD_NOLOAD).is_err());
        assert_eq!(api::dlclose(handle), 0);
        drop(via_os_str);
        drop(library);

        let library = ElfLibrary::dlopen(&path, OpenFlags::RTLD_NOW).unwrap();
        let answer = library
            .get::<unsafe extern "C" fn() -> i32>("non_utf8_answer")
            .unwrap();
        assert_eq!(answer(), 42);
    }
    std::fs::remove_dir_all(dir).unwrap();
}
