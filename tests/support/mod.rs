use std::{path::Path, process::Command};

pub(crate) fn apply_local_relink_patch(cmd: &mut Command) {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let Some(parent) = manifest_dir.parent() else {
        return;
    };
    let relink = parent.join("Relink");
    if !relink.join("Cargo.toml").is_file() {
        return;
    }

    cmd.arg("--config").arg(format!(
        "patch.\"https://github.com/weizhiao/Relink.git\".elf_loader.path=\"{}\"",
        relink.display()
    ));
}
