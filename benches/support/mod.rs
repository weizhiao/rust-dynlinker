#[path = "../../tests/support/dylib.rs"]
mod dylib;

use std::{path::PathBuf, sync::Once};

pub(crate) fn example_dylib_path() -> PathBuf {
    static BUILD_EXAMPLE: Once = Once::new();
    BUILD_EXAMPLE.call_once(|| dylib::build_dylibs(&["example_dylib"]));
    dylib::lib_path("libexample.so")
}
