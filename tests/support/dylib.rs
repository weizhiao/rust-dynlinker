#[path = "cargo.rs"]
mod cargo;

use std::{env, path::PathBuf};

fn target_triple() -> &'static str {
    match env::consts::ARCH {
        "x86_64" => "x86_64-unknown-linux-gnu",
        "aarch64" => "aarch64-unknown-linux-gnu",
        "riscv64" => "riscv64gc-unknown-linux-gnu",
        "loongarch64" => "loongarch64-unknown-linux-musl",
        arch => panic!("unsupported fixture arch: {arch}"),
    }
}

pub(crate) fn lib_path(file_name: &str) -> PathBuf {
    cargo::target_dir()
        .join(target_triple())
        .join("release")
        .join(file_name)
}

pub(crate) fn build_dylibs(packages: &[&str]) {
    let mut command = cargo::cargo_command();
    command
        .args(["build", "--release", "--target", target_triple()])
        .env("CARGO_PROFILE_RELEASE_PANIC", "unwind");
    for package in packages {
        command.args(["-p", package]);
    }
    assert!(
        command
            .status()
            .expect("could not compile the test helpers")
            .success(),
        "failed to compile test helper packages {packages:?}"
    );
}
