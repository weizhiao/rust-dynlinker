#[path = "support/dylib.rs"]
mod support;

use dlopen_rs::{ElfLibrary, OpenFlags};
use std::fs;
use support::lib_path;

fn compile() {
    static ONCE: ::std::sync::Once = ::std::sync::Once::new();
    ONCE.call_once(|| support::build_dylibs(&["example_dylib"]));
}

/// Test to verify that inode checking prevents duplicate loads via symlinks
#[cfg(unix)]
#[test]
fn test_symlink_inode_detection() {
    compile();

    // Get the path to the compiled test library
    let original_path = lib_path("libexample.so");

    // Ensure the library exists and convert to absolute path
    let original_path = fs::canonicalize(&original_path)
        .unwrap_or_else(|_| panic!("Failed to find library at: {}", original_path.display()));

    println!("Original library path: {:?}", original_path);

    // Create a temporary directory for our test
    let temp_dir = std::env::temp_dir().join("dlopen_inode_test_symlink");
    let _ = fs::remove_dir_all(&temp_dir); // Clean start
    let _ = fs::create_dir_all(&temp_dir);

    let symlink_path = temp_dir.join("libexample_symlink.so");

    // Create a symlink to the test library
    std::os::unix::fs::symlink(&original_path, &symlink_path).expect("Failed to create symlink");

    println!("Symlink created at: {:?}", symlink_path);

    // Load via original path
    let lib1 = ElfLibrary::dlopen(&original_path, OpenFlags::RTLD_NOW | OpenFlags::RTLD_LOCAL)
        .expect("Failed to load library via original path");

    // Load via symlink - should return the same library instance
    let lib2 = ElfLibrary::dlopen(&symlink_path, OpenFlags::RTLD_NOW | OpenFlags::RTLD_LOCAL)
        .expect("Failed to load library via symlink");

    // Verify they have the same base address (same library instance)
    assert_eq!(
        lib1.base(),
        lib2.base(),
        "Libraries loaded via different paths should have same base address due to inode checking"
    );

    let lib3 = ElfLibrary::dlopen(&symlink_path, OpenFlags::RTLD_NOLOAD)
        .expect("RTLD_NOLOAD should find the library via symlink identity");
    assert_eq!(lib1.base(), lib3.base());

    // Cleanup
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_relative_path_deduplication() {
    compile();
    let original_path = lib_path("libexample.so");
    let original_path = fs::canonicalize(&original_path).unwrap();
    let dir = original_path.parent().unwrap();
    let filename = original_path.file_name().unwrap().to_str().unwrap();

    // 1. Load via absolute path
    let lib1 = ElfLibrary::dlopen(&original_path, OpenFlags::RTLD_NOW | OpenFlags::RTLD_LOCAL)
        .expect("Failed to load absolute path");

    // 2. Load via relative path (change cwd to the lib dir)
    let cwd = std::env::current_dir().unwrap();
    std::env::set_current_dir(dir).unwrap();

    let relative_path = format!("./{}", filename);
    let lib2 = ElfLibrary::dlopen(&relative_path, OpenFlags::RTLD_NOW | OpenFlags::RTLD_LOCAL)
        .expect("Failed to load relative path");

    // Restore cwd
    std::env::set_current_dir(cwd).unwrap();

    assert_eq!(
        lib1.base(),
        lib2.base(),
        "Relative path load should be deduplicated"
    );
}

#[test]
fn test_non_existent_file_fail_fast() {
    // Test that a non-existent file with explicit path fails immediately
    let result = ElfLibrary::dlopen("/tmp/non_existent_library_XYZ.so", OpenFlags::RTLD_NOW);
    assert!(result.is_err());

    // The error message should indicate file not found, not something from the search path iteration
    let err_msg = result.err().unwrap().to_string();
    println!("Error message: {}", err_msg);
    // Note: exact error message depends on implementation, but it should fail.
}
