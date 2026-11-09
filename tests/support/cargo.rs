use std::{env, path::PathBuf, process::Command};

pub(crate) fn target_dir() -> PathBuf {
    let path = env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .or_else(|| option_env!("CARGO_TARGET_DIR").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("target"));
    // Tests may change the process cwd while another test prepares its fixtures.
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path)
}

pub(crate) fn cargo_command() -> Command {
    let mut command = Command::new("cargo");
    command
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env("CARGO_TARGET_DIR", target_dir());
    command
}
