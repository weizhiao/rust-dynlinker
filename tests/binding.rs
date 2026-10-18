#![cfg(all(target_os = "linux", feature = "std"))]

use dlopen_rs::{ElfLibrary, OpenFlags};
use std::{fs, process::Command};

#[test]
fn binding_policy_respects_request_and_elf_flags() {
    let dir = std::env::temp_dir().join(format!("dlopen-binding-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let source = dir.join("fixture.c");
    fs::write(
        &source,
        "extern int missing_binding_test_symbol(void);\nint call_missing(void) { return missing_binding_test_symbol(); }\n",
    )
    .unwrap();
    for mode in ["lazy", "now"] {
        let path = dir.join(format!("lib{mode}.so"));
        assert!(
            Command::new("cc")
                .args(["-shared", "-fPIC", "-nostdlib", "-Wl,-z"])
                .arg(format!("-Wl,{mode}"))
                .arg(&source)
                .arg("-o")
                .arg(&path)
                .status()
                .unwrap()
                .success()
        );
        // RTLD_NOW must resolve even an ELF that permits lazy binding.
        assert!(ElfLibrary::dlopen(&path, OpenFlags::RTLD_NOW).is_err());
        let loaded = ElfLibrary::dlopen(&path, OpenFlags::RTLD_LAZY);
        if mode == "lazy" {
            // Do not call the intentionally unresolved function.
            drop(loaded.unwrap());
        } else {
            // RTLD_LAZY must not override the ELF's own immediate-binding requirement.
            assert!(loaded.is_err());
        }
    }
    fs::remove_dir_all(dir).unwrap();
}
