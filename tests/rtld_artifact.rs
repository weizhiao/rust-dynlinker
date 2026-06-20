#![cfg(target_arch = "x86_64")]

mod support;

use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::OnceLock,
};

const RTLD_TARGET: &str = "x86_64-unknown-linux-none";

fn target_dir() -> PathBuf {
    option_env!("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("target"))
}

fn rtld_path() -> PathBuf {
    target_dir()
        .join(RTLD_TARGET)
        .join("release")
        .join("librtld.so")
}

fn rtld_interp_path() -> PathBuf {
    target_dir()
        .join(RTLD_TARGET)
        .join("release")
        .join("ld-linux-x86-64.so.2")
}

fn has_command(program: &str) -> bool {
    Command::new(program)
        .arg("--version")
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

fn command_output(program: &str, args: &[&str]) -> String {
    let output = Command::new(program)
        .args(args)
        .output()
        .unwrap_or_else(|err| panic!("failed to run {program}: {err}"));
    assert!(
        output.status.success(),
        "{program} {args:?} failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("command output must be utf-8")
}

fn first_existing_path(candidates: &[&str]) -> Option<PathBuf> {
    candidates
        .iter()
        .map(PathBuf::from)
        .find(|path| path.exists())
}

type SymbolId = (String, Option<String>);

fn parse_symbol_id(name: &str) -> SymbolId {
    let Some((name, version)) = name.split_once('@') else {
        return (name.to_owned(), None);
    };
    let version = version.trim_start_matches('@');
    (
        name.to_owned(),
        (!version.is_empty()).then(|| version.to_owned()),
    )
}

fn format_symbol_id((name, version): &SymbolId) -> String {
    match version {
        Some(version) => format!("{name}@{version}"),
        None => name.clone(),
    }
}

fn readelf_symbols(path: &Path) -> Vec<Vec<String>> {
    let symbols = command_output("readelf", &["-Ws", path.to_str().unwrap()]);
    symbols
        .lines()
        .map(|line| {
            line.split_whitespace()
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .filter(|fields| fields.len() >= 8 && fields[0].ends_with(':'))
        .collect()
}

fn undefined_symbols(path: &Path) -> BTreeSet<SymbolId> {
    readelf_symbols(path)
        .into_iter()
        .filter(|fields| fields[6] == "UND")
        .map(|fields| parse_symbol_id(&fields[7]))
        .filter(|(name, _)| !name.is_empty())
        .collect()
}

fn exported_symbols(path: &Path) -> BTreeSet<SymbolId> {
    readelf_symbols(path)
        .into_iter()
        .filter(|fields| matches!(fields[3].as_str(), "FUNC" | "OBJECT" | "NOTYPE"))
        .filter(|fields| matches!(fields[4].as_str(), "GLOBAL" | "WEAK"))
        .filter(|fields| fields[6] != "UND")
        .map(|fields| parse_symbol_id(&fields[7]))
        .filter(|(name, _)| !name.is_empty())
        .collect()
}

fn cargo_is_nightly() -> bool {
    static IS_NIGHTLY: OnceLock<bool> = OnceLock::new();

    *IS_NIGHTLY.get_or_init(|| {
        Command::new("cargo")
            .arg("--version")
            .output()
            .map(|output| {
                output.status.success()
                    && String::from_utf8_lossy(&output.stdout).contains("-nightly")
            })
            .unwrap_or(false)
    })
}

fn build_rtld() -> Option<PathBuf> {
    if !cargo_is_nightly() {
        eprintln!(
            "skipping rtld artifact test because building the rtld artifact requires nightly Cargo"
        );
        return None;
    }

    let mut cmd = Command::new("cargo");
    cmd.args([
        "-Z",
        "build-std=core,alloc,compiler_builtins",
        "build",
        "-p",
        "rtld",
        "--release",
        "--target",
        RTLD_TARGET,
    ]);
    support::apply_local_relink_patch(&mut cmd);
    let output = cmd.output().expect("failed to invoke cargo");
    assert!(
        output.status.success(),
        "rtld release build failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Some(rtld_path())
}

fn test_work_dir(name: &str) -> PathBuf {
    let dir = target_dir().join("rtld-tests").join(name);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn c_string_literal(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

#[test]
fn rtld_artifact_has_interpreter_shape() {
    let Some(path) = build_rtld() else {
        return;
    };
    assert!(path.exists(), "missing artifact at {}", path.display());
    let path = path.to_str().unwrap();

    let headers = command_output("readelf", &["-h", path]);
    let entry_line = headers
        .lines()
        .find(|line| line.contains("Entry point address:"))
        .expect("readelf -h should include entry point");
    assert!(
        !entry_line.ends_with("0x0"),
        "interpreter entry must be nonzero: {entry_line}"
    );

    let dynamic = command_output("readelf", &["-d", path]);
    assert!(
        dynamic.contains("Library soname: [ld-linux-x86-64.so.2]"),
        "interpreter must advertise ld-linux soname\n{dynamic}"
    );
    assert!(
        !dynamic.contains("(NEEDED)"),
        "interpreter artifact must be self-contained\n{dynamic}"
    );
    let relocations = command_output("readelf", &["-r", path]);
    assert!(
        relocations.contains("R_X86_64_RELATIVE"),
        "interpreter should exercise its own RELATIVE relocation path\n{relocations}"
    );
    assert!(
        !relocations
            .lines()
            .any(|line| line.contains("R_X86_64_") && !line.contains("R_X86_64_RELATIVE")),
        "stage-0 interpreter may only need RELATIVE relocations\n{relocations}"
    );

    let symbols = command_output("readelf", &["-Ws", path]);
    for symbol in [
        "_r_debug",
        "_dl_debug_state",
        "__tls_get_addr",
        "_dl_find_object",
        "_dl_find_dso_for_object",
        "_rtld_global",
        "_rtld_global_ro",
        "_dl_argv",
    ] {
        assert!(symbols.contains(symbol), "missing symbol {symbol}");
    }
    assert!(
        !symbols.contains("__dlopen_rtld_bootstrap_state"),
        "bootstrap state should be passed internally, not exported\n{symbols}"
    );
    for version in [
        "GLIBC_2.2.5",
        "GLIBC_2.3",
        "GLIBC_2.34",
        "GLIBC_2.35",
        "GLIBC_PRIVATE",
    ] {
        assert!(symbols.contains(version), "missing version {version}");
    }
    assert!(
        symbols.lines().any(|line| {
            line.contains("_rtld_global@@GLIBC_PRIVATE")
                && line.split_whitespace().nth(2) == Some("2120")
        }),
        "_rtld_global must keep glibc's x86_64 size\n{symbols}"
    );
    assert!(
        symbols.lines().any(|line| {
            line.contains("_rtld_global_ro@@GLIBC_PRIVATE")
                && line.split_whitespace().nth(2) == Some("928")
        }),
        "_rtld_global_ro must keep glibc's x86_64 size\n{symbols}"
    );
}

#[test]
fn rtld_artifact_exports_libc_needed_ld_so_symbols() {
    if !has_command("readelf") {
        eprintln!("skipping libc/ld.so symbol ABI test because readelf is unavailable");
        return;
    }

    let Some(path) = build_rtld() else {
        return;
    };
    let Some(libc) = first_existing_path(&[
        "/lib/x86_64-linux-gnu/libc.so.6",
        "/usr/lib/x86_64-linux-gnu/libc.so.6",
        "/lib64/libc.so.6",
    ]) else {
        eprintln!("skipping libc/ld.so symbol ABI test because libc.so.6 was not found");
        return;
    };
    let Some(system_rtld) = first_existing_path(&[
        "/lib64/ld-linux-x86-64.so.2",
        "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
        "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
    ]) else {
        eprintln!(
            "skipping libc/ld.so symbol ABI test because system ld-linux-x86-64.so.2 was not found"
        );
        return;
    };

    let libc_undefined = undefined_symbols(&libc);
    let system_rtld_exports = exported_symbols(&system_rtld);
    let required = libc_undefined
        .intersection(&system_rtld_exports)
        .cloned()
        .collect::<BTreeSet<_>>();
    assert!(
        required.contains(&("__tls_get_addr".to_owned(), Some("GLIBC_2.3".to_owned())))
            && required.contains(&("_rtld_global".to_owned(), Some("GLIBC_PRIVATE".to_owned()))),
        "test did not discover expected libc-private ld.so requirements: {required:?}"
    );

    let rtld_exports = exported_symbols(&path);
    let missing = required
        .difference(&rtld_exports)
        .map(format_symbol_id)
        .collect::<Vec<_>>();
    let required = required.iter().map(format_symbol_id).collect::<Vec<_>>();
    assert!(
        missing.is_empty(),
        "rtld artifact is missing libc-required ld.so exports: {missing:?}\nrequired: {required:?}"
    );
}

#[test]
fn rtld_artifact_can_be_loaded_as_pt_interp() {
    if !has_command("cc") || !has_command("patchelf") {
        eprintln!("skipping PT_INTERP smoke test because cc or patchelf is unavailable");
        return;
    }

    let Some(_artifact) = build_rtld() else {
        return;
    };
    let interp = rtld_interp_path();
    assert!(interp.exists(), "missing {}", interp.display());

    let dir = test_work_dir("pt-interp");
    let source = dir.join("hello.c");
    let program = dir.join("hello");
    fs::write(
        &source,
        br#"
int main(void) {
    return 0;
}
"#,
    )
    .unwrap();

    assert!(
        Command::new("cc")
            .arg(&source)
            .arg("-o")
            .arg(&program)
            .status()
            .expect("failed to compile test program")
            .success(),
        "failed to compile test program"
    );
    assert!(
        Command::new("patchelf")
            .arg("--set-interpreter")
            .arg(&interp)
            .arg(&program)
            .status()
            .expect("failed to patch interpreter")
            .success(),
        "failed to patch interpreter"
    );

    let output = Command::new(&program)
        .output()
        .expect("failed to execute patched program");
    assert!(
        output.stderr.is_empty(),
        "unexpected stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn rtld_artifact_can_start_glibc_program() {
    if !has_command("cc") {
        eprintln!("skipping glibc PT_INTERP test because cc is unavailable");
        return;
    }

    let Some(_artifact) = build_rtld() else {
        return;
    };
    let interp = rtld_interp_path();
    assert!(interp.exists(), "missing {}", interp.display());

    let dir = test_work_dir("pt-interp-glibc");
    let source = dir.join("libc_exit.c");
    let program = dir.join("libc_exit");
    fs::write(
        &source,
        br#"
int main(void) {
    return 33;
}
"#,
    )
    .unwrap();

    assert!(
        Command::new("cc")
            .arg(&source)
            .arg(format!("-Wl,--dynamic-linker={}", interp.display()))
            .arg("-o")
            .arg(&program)
            .status()
            .expect("failed to compile glibc test program")
            .success(),
        "failed to compile glibc test program"
    );

    let dynamic = command_output("readelf", &["-d", program.to_str().unwrap()]);
    assert!(
        dynamic.contains("(NEEDED)") && dynamic.contains("libc.so.6"),
        "test program must need libc\n{dynamic}"
    );

    let output = Command::new(&program)
        .output()
        .expect("failed to execute glibc test program");
    assert!(
        output.stderr.is_empty(),
        "unexpected stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.status.code(), Some(33));
}

#[test]
fn rtld_artifact_can_run_simple_c_program() {
    if !has_command("cc") {
        eprintln!("skipping simple C PT_INTERP test because cc is unavailable");
        return;
    }

    let Some(_artifact) = build_rtld() else {
        return;
    };
    let interp = rtld_interp_path();
    assert!(interp.exists(), "missing {}", interp.display());

    let dir = test_work_dir("pt-interp-simple-c");
    let source = dir.join("simple.c");
    let program = dir.join("simple");
    fs::write(
        &source,
        br#"
#include <stdio.h>

static int value = 5;

int main(void) {
    printf("rtld:%d\n", value + 2);
    return value + 2;
}
"#,
    )
    .unwrap();

    assert!(
        Command::new("cc")
            .arg(&source)
            .arg(format!("-Wl,--dynamic-linker={}", interp.display()))
            .arg("-o")
            .arg(&program)
            .status()
            .expect("failed to compile simple C test program")
            .success(),
        "failed to compile simple C test program"
    );

    let dynamic = command_output("readelf", &["-d", program.to_str().unwrap()]);
    assert!(
        dynamic.contains("(NEEDED)") && dynamic.contains("libc.so.6"),
        "test program must need libc\n{dynamic}"
    );

    let output = Command::new(&program)
        .output()
        .expect("failed to execute simple C test program");
    assert!(
        output.stderr.is_empty(),
        "unexpected stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "rtld:7\n");
    assert_eq!(output.status.code(), Some(7));
}

#[test]
fn rtld_artifact_can_create_pthread_with_local_exec_tls() {
    if !has_command("cc") {
        eprintln!("skipping pthread TLS PT_INTERP test because cc is unavailable");
        return;
    }

    let Some(_artifact) = build_rtld() else {
        return;
    };
    let interp = rtld_interp_path();
    assert!(interp.exists(), "missing {}", interp.display());

    let dir = test_work_dir("pt-interp-pthread-tls");
    let source = dir.join("pthread_tls.c");
    let program = dir.join("pthread_tls");
    fs::write(
        &source,
        br#"
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>

static __thread int tls_value __attribute__((tls_model("local-exec"))) = 3;

static void *worker(void *arg) {
    tls_value += (int)(intptr_t)arg;
    return (void *)(intptr_t)tls_value;
}

int main(void) {
    pthread_t thread;
    void *ret = 0;
    tls_value = 7;
    if (pthread_create(&thread, 0, worker, (void *)(intptr_t)5) != 0) {
        return 10;
    }
    if (pthread_join(thread, &ret) != 0) {
        return 11;
    }
    printf("pthread-tls:%ld:%d\n", (long)(intptr_t)ret, tls_value);
    return (intptr_t)ret == 8 && tls_value == 7 ? 0 : 12;
}
"#,
    )
    .unwrap();

    assert!(
        Command::new("cc")
            .arg(&source)
            .arg("-pthread")
            .arg(format!("-Wl,--dynamic-linker={}", interp.display()))
            .arg("-o")
            .arg(&program)
            .status()
            .expect("failed to compile pthread TLS test program")
            .success(),
        "failed to compile pthread TLS test program"
    );

    let output = Command::new(&program)
        .output()
        .expect("failed to execute pthread TLS test program");
    assert!(
        output.stderr.is_empty(),
        "unexpected stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.status.success(),
        "pthread TLS test failed with {:?}\nstdout:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "pthread-tls:8:7\n");
}

#[test]
fn rtld_artifact_reports_tls_data_from_dl_iterate_phdr() {
    if !has_command("cc") {
        eprintln!("skipping dl_iterate_phdr TLS PT_INTERP test because cc is unavailable");
        return;
    }

    let Some(_artifact) = build_rtld() else {
        return;
    };
    let interp = rtld_interp_path();
    assert!(interp.exists(), "missing {}", interp.display());

    let dir = test_work_dir("pt-interp-phdr-tls");
    let source = dir.join("phdr_tls.c");
    let program = dir.join("phdr_tls");
    fs::write(
        &source,
        br#"
#define _GNU_SOURCE
#include <elf.h>
#include <link.h>
#include <stdint.h>
#include <stdio.h>

static __thread int tls_value __attribute__((tls_model("local-exec"))) = 123;
static int found;

static int callback(struct dl_phdr_info *info, size_t size, void *data) {
    (void) size;
    (void) data;
    if (info->dlpi_tls_modid == 0 || info->dlpi_tls_data == 0) {
        return 0;
    }

    uintptr_t tls_addr = (uintptr_t) &tls_value;
    for (ElfW(Half) i = 0; i < info->dlpi_phnum; ++i) {
        const ElfW(Phdr) *phdr = &info->dlpi_phdr[i];
        if (phdr->p_type != PT_TLS) {
            continue;
        }
        uintptr_t start = (uintptr_t) info->dlpi_tls_data;
        uintptr_t end = start + phdr->p_memsz;
        if (start <= tls_addr && tls_addr < end) {
            found = (int) info->dlpi_tls_modid;
            return 1;
        }
    }
    return 0;
}

int main(void) {
    tls_value = 321;
    dl_iterate_phdr(callback, 0);
    if (found == 0 || tls_value != 321) {
        return 10;
    }
    printf("phdr-tls:%d:%d\n", found, tls_value);
    return 0;
}
"#,
    )
    .unwrap();

    assert!(
        Command::new("cc")
            .arg(&source)
            .arg(format!("-Wl,--dynamic-linker={}", interp.display()))
            .arg("-o")
            .arg(&program)
            .status()
            .expect("failed to compile dl_iterate_phdr TLS test program")
            .success(),
        "failed to compile dl_iterate_phdr TLS test program"
    );

    let output = Command::new(&program)
        .output()
        .expect("failed to execute dl_iterate_phdr TLS test program");
    assert!(
        output.stderr.is_empty(),
        "unexpected stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.status.success(),
        "dl_iterate_phdr TLS test failed with {:?}\nstdout:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).starts_with("phdr-tls:"),
        "unexpected stdout:\n{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn rtld_artifact_publishes_glibc_rtld_globals() {
    if !has_command("cc") {
        eprintln!("skipping rtld globals ABI test because cc is unavailable");
        return;
    }

    let Some(_artifact) = build_rtld() else {
        return;
    };
    let interp = rtld_interp_path();
    assert!(interp.exists(), "missing {}", interp.display());

    let dir = test_work_dir("pt-interp-rtld-globals");
    let source = dir.join("globals.c");
    let program = dir.join("globals");
    fs::write(
        &source,
        br#"
#define _GNU_SOURCE
#include <link.h>
#include <stdio.h>
#include <unistd.h>

static int seen;

static int callback(struct dl_phdr_info *info, size_t size, void *data) {
    (void) size;
    (void) data;
    if (info->dlpi_phdr != 0 && info->dlpi_phnum != 0) {
        ++seen;
    }
    return 0;
}

int main(void) {
    int pagesize = getpagesize();
    long sys_pagesize = sysconf(_SC_PAGESIZE);
    long clktck = sysconf(_SC_CLK_TCK);

    if (pagesize <= 0 || sys_pagesize != pagesize || clktck <= 0) {
        return 10;
    }
    if (dl_iterate_phdr(callback, 0) != 0 || seen == 0) {
        return 11;
    }

    printf("globals:%d:%ld:%d\n", pagesize, clktck, seen);
    return 0;
}
"#,
    )
    .unwrap();

    assert!(
        Command::new("cc")
            .arg(&source)
            .arg(format!("-Wl,--dynamic-linker={}", interp.display()))
            .arg("-o")
            .arg(&program)
            .status()
            .expect("failed to compile rtld globals ABI test program")
            .success(),
        "failed to compile rtld globals ABI test program"
    );

    let output = Command::new(&program)
        .output()
        .expect("failed to execute rtld globals ABI test program");
    assert!(
        output.stderr.is_empty(),
        "unexpected stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.status.success(),
        "rtld globals ABI test failed with {:?}\nstdout:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).starts_with("globals:"),
        "unexpected stdout:\n{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn rtld_artifact_exposes_glibc_tunable_defaults() {
    if !has_command("cc") {
        eprintln!("skipping tunables PT_INTERP test because cc is unavailable");
        return;
    }

    let Some(_artifact) = build_rtld() else {
        return;
    };
    let interp = rtld_interp_path();
    assert!(interp.exists(), "missing {}", interp.display());

    let dir = test_work_dir("pt-interp-tunables");
    let source = dir.join("tunables.c");
    let program = dir.join("tunables");
    fs::write(
        &source,
        br#"
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

struct tunable_str_t {
    const char *str;
    size_t len;
};

typedef void (*tunable_get_val_fn)(size_t, void *, void *);
typedef bool (*tunable_is_initialized_fn)(size_t);

enum {
    glibc_cpu_hwcaps = 0,
    glibc_pthread_stack_cache_size = 29,
    glibc_rtld_dynamic_sort = 31,
    glibc_rtld_optional_static_tls = 35,
};

int main(void) {
    tunable_get_val_fn get_val =
        (tunable_get_val_fn) dlsym(RTLD_DEFAULT, "__tunable_get_val");
    tunable_is_initialized_fn is_initialized =
        (tunable_is_initialized_fn) dlsym(RTLD_DEFAULT, "__tunable_is_initialized");
    if (get_val == 0 || is_initialized == 0) {
        return 10;
    }

    size_t stack_cache_size = 0;
    int dynamic_sort = 0;
    size_t optional_static_tls = 0;
    const struct tunable_str_t *hwcaps = (const struct tunable_str_t *) 1;

    get_val(glibc_pthread_stack_cache_size, &stack_cache_size, 0);
    get_val(glibc_rtld_dynamic_sort, &dynamic_sort, 0);
    get_val(glibc_rtld_optional_static_tls, &optional_static_tls, 0);
    get_val(glibc_cpu_hwcaps, &hwcaps, 0);

    if (is_initialized(glibc_rtld_optional_static_tls)) {
        return 11;
    }
    if (stack_cache_size != 41943040) {
        return 12;
    }
    if (dynamic_sort != 2) {
        return 13;
    }
    if (optional_static_tls != 512) {
        return 14;
    }
    if (hwcaps == 0 || hwcaps->str != 0 || hwcaps->len != 0) {
        return 15;
    }

    printf("tunables:%zu:%d:%zu:%zu\n",
           stack_cache_size, dynamic_sort, optional_static_tls, hwcaps->len);
    return 0;
}
"#,
    )
    .unwrap();

    assert!(
        Command::new("cc")
            .arg(&source)
            .arg(format!("-Wl,--dynamic-linker={}", interp.display()))
            .arg("-o")
            .arg(&program)
            .status()
            .expect("failed to compile tunables ABI test program")
            .success(),
        "failed to compile tunables ABI test program"
    );

    let output = Command::new(&program)
        .output()
        .expect("failed to execute tunables ABI test program");
    assert!(
        output.stderr.is_empty(),
        "unexpected stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.status.success(),
        "tunables ABI test failed with {:?}\nstdout:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "tunables:41943040:2:512:0\n"
    );
}

#[test]
fn rtld_artifact_reports_dlinfo_search_paths() {
    if !has_command("cc") {
        eprintln!("skipping dlinfo SERINFO PT_INTERP test because cc is unavailable");
        return;
    }

    let Some(_artifact) = build_rtld() else {
        return;
    };
    let interp = rtld_interp_path();
    assert!(interp.exists(), "missing {}", interp.display());

    let dir = test_work_dir("pt-interp-dlinfo-serinfo");
    let source = dir.join("serinfo.c");
    let program = dir.join("serinfo");
    fs::write(
        &source,
        br#"
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    Dl_serinfo info;
    memset(&info, 0, sizeof(info));
    void *handle = (void *) 1;

    if (dlinfo(handle, RTLD_DI_SERINFOSIZE, &info) != 0) {
        return 11;
    }
    if (info.dls_cnt == 0 || info.dls_size < sizeof(Dl_serinfo)) {
        return 12;
    }

    Dl_serinfo *full = malloc(info.dls_size);
    if (full == 0) {
        return 13;
    }
    full->dls_size = info.dls_size;
    full->dls_cnt = info.dls_cnt;
    if (dlinfo(handle, RTLD_DI_SERINFO, full) != 0) {
        return 14;
    }

    int found_default = 0;
    for (unsigned int i = 0; i < full->dls_cnt; ++i) {
        const char *name = full->dls_serpath[i].dls_name;
        if (name != 0 && (strcmp(name, "/usr/lib") == 0
                || strstr(name, "x86_64-linux-gnu") != 0)) {
            found_default = 1;
        }
    }

    printf("serinfo:%u:%zu:%s\n", full->dls_cnt, full->dls_size,
           full->dls_serpath[0].dls_name);
    free(full);
    return found_default ? 0 : 15;
}

"#,
    )
    .unwrap();

    assert!(
        Command::new("cc")
            .arg(&source)
            .arg(format!("-Wl,--dynamic-linker={}", interp.display()))
            .arg("-o")
            .arg(&program)
            .status()
            .expect("failed to compile dlinfo SERINFO test program")
            .success(),
        "failed to compile dlinfo SERINFO test program"
    );

    let output = Command::new(&program)
        .output()
        .expect("failed to execute dlinfo SERINFO test program");
    assert!(
        output.stderr.is_empty(),
        "unexpected stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.status.success(),
        "dlinfo SERINFO test failed with {:?}\nstdout:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).starts_with("serinfo:"),
        "unexpected stdout:\n{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn rtld_artifact_reports_dlinfo_origin() {
    if !has_command("cc") {
        eprintln!("skipping dlinfo ORIGIN PT_INTERP test because cc is unavailable");
        return;
    }

    let Some(_artifact) = build_rtld() else {
        return;
    };
    let interp = rtld_interp_path();
    assert!(interp.exists(), "missing {}", interp.display());

    let dir = test_work_dir("pt-interp-dlinfo-origin");
    let plugin_source = dir.join("plugin.c");
    let plugin = dir.join("liborigin_plugin.so");
    let source = dir.join("origin.c");
    let program = dir.join("origin");
    fs::write(
        &plugin_source,
        br#"
int origin_plugin_value(void) {
    return 7;
}
"#,
    )
    .unwrap();
    assert!(
        Command::new("cc")
            .arg("-shared")
            .arg("-fPIC")
            .arg(&plugin_source)
            .arg("-o")
            .arg(&plugin)
            .status()
            .expect("failed to compile origin plugin")
            .success(),
        "failed to compile origin plugin"
    );

    let plugin_path = c_string_literal(plugin.to_str().unwrap());
    let expected_origin = c_string_literal(dir.to_str().unwrap());
    fs::write(
        &source,
        format!(
            r#"
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

#ifndef RTLD_DI_ORIGIN_PATH
#define RTLD_DI_ORIGIN_PATH 12
#endif

int main(void) {{
    void *handle = dlopen("{plugin_path}", RTLD_NOW | RTLD_LOCAL);
    if (handle == 0) {{
        return 10;
    }}

    char origin[4096];
    memset(origin, 0, sizeof(origin));
    if (dlinfo(handle, RTLD_DI_ORIGIN, origin) != 0) {{
        const char *err = dlerror();
        printf("origin-error:%s\n", err == 0 ? "" : err);
        return 11;
    }}

    const char *origin_path = (const char *) 1;
    if (dlinfo(handle, RTLD_DI_ORIGIN_PATH, &origin_path) != 0) {{
        const char *err = dlerror();
        printf("origin-path-error:%s\n", err == 0 ? "" : err);
        return 12;
    }}

    int ok = strcmp(origin, "{expected_origin}") == 0
        && origin_path != 0
        && strcmp(origin_path, "{expected_origin}") == 0;
    printf("origin:%s:%s\n", origin, origin_path == 0 ? "" : origin_path);
    dlclose(handle);
    return ok ? 0 : 13;
}}
"#
        ),
    )
    .unwrap();

    assert!(
        Command::new("cc")
            .arg(&source)
            .arg(format!("-Wl,--dynamic-linker={}", interp.display()))
            .arg("-o")
            .arg(&program)
            .status()
            .expect("failed to compile dlinfo ORIGIN test program")
            .success(),
        "failed to compile dlinfo ORIGIN test program"
    );

    let output = Command::new(&program)
        .output()
        .expect("failed to execute dlinfo ORIGIN test program");
    assert!(
        output.stderr.is_empty(),
        "unexpected stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.status.success(),
        "dlinfo ORIGIN test failed with {:?}\nstdout:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        format!("origin:{}:{}\n", dir.display(), dir.display())
    );
}

#[test]
fn rtld_artifact_supports_libc_dlfcn_hook() {
    if !has_command("cc") {
        eprintln!("skipping dlfcn PT_INTERP test because cc is unavailable");
        return;
    }

    let Some(_artifact) = build_rtld() else {
        return;
    };
    let interp = rtld_interp_path();
    assert!(interp.exists(), "missing {}", interp.display());

    let dir = test_work_dir("pt-interp-dlfcn-hook");
    let plugin_source = dir.join("plugin.c");
    let plugin = dir.join("libplugin.so");
    let source = dir.join("dlfcn_hook.c");
    let program = dir.join("dlfcn_hook");
    fs::write(
        &plugin_source,
        br#"
int plugin_value(void) {
    return 42;
}
"#,
    )
    .unwrap();
    assert!(
        Command::new("cc")
            .arg("-shared")
            .arg("-fPIC")
            .arg(&plugin_source)
            .arg("-o")
            .arg(&plugin)
            .status()
            .expect("failed to compile plugin")
            .success(),
        "failed to compile plugin"
    );

    let plugin_path = c_string_literal(plugin.to_str().unwrap());
    fs::write(
        &source,
        format!(
            r#"
#include <dlfcn.h>
#include <stdio.h>

typedef int (*plugin_value_fn)(void);

int main(void) {{
    void *handle = dlopen("{plugin_path}", RTLD_NOW | RTLD_LOCAL);
    if (handle == 0) {{
        const char *err = dlerror();
        printf("dlopen-error:%s\n", err == 0 ? "" : err);
        return 10;
    }}

    plugin_value_fn plugin_value = (plugin_value_fn) dlsym(handle, "plugin_value");
    if (plugin_value == 0) {{
        const char *err = dlerror();
        printf("dlsym-error:%s\n", err == 0 ? "" : err);
        return 11;
    }}

    int value = plugin_value();
    int closed = dlclose(handle);
    printf("dlfcn:%d:%d\n", value, closed);
    return value == 42 && closed == 0 ? 0 : 12;
}}
"#
        ),
    )
    .unwrap();

    assert!(
        Command::new("cc")
            .arg(&source)
            .arg(format!("-Wl,--dynamic-linker={}", interp.display()))
            .arg("-o")
            .arg(&program)
            .status()
            .expect("failed to compile dlfcn test program")
            .success(),
        "failed to compile dlfcn test program"
    );

    let output = Command::new(&program)
        .output()
        .expect("failed to execute dlfcn test program");
    assert!(
        output.stderr.is_empty(),
        "unexpected stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.status.success(),
        "dlfcn test failed with {:?}\nstdout:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "dlfcn:42:0\n");
}

#[test]
fn rtld_artifact_has_command_line_help_and_version() {
    let Some(_artifact) = build_rtld() else {
        return;
    };
    let interp = rtld_interp_path();
    assert!(interp.exists(), "missing {}", interp.display());

    let help = Command::new(&interp)
        .arg("--help")
        .output()
        .expect("failed to execute rtld --help");
    assert!(
        help.status.success(),
        "rtld --help failed with {:?}",
        help.status.code()
    );
    assert!(
        help.stderr.is_empty(),
        "unexpected stderr:\n{}",
        String::from_utf8_lossy(&help.stderr)
    );
    let help = String::from_utf8(help.stdout).expect("help output must be utf-8");
    assert!(help.contains("Usage:"), "{help}");
    assert!(help.contains("--list"), "{help}");
    assert!(help.contains("--verify"), "{help}");
    assert!(help.contains("ld-linux-x86-64.so.2"), "{help}");

    let version = Command::new(&interp)
        .arg("--version")
        .output()
        .expect("failed to execute rtld --version");
    assert!(
        version.status.success(),
        "rtld --version failed with {:?}",
        version.status.code()
    );
    assert!(
        version.stderr.is_empty(),
        "unexpected stderr:\n{}",
        String::from_utf8_lossy(&version.stderr)
    );
    let version = String::from_utf8(version.stdout).expect("version output must be utf-8");
    assert!(version.contains("dlopen-rs rtld"), "{version}");
}

#[test]
fn rtld_artifact_command_line_can_verify_and_list_simple_c_program() {
    if !has_command("cc") {
        eprintln!("skipping rtld CLI test because cc is unavailable");
        return;
    }

    let Some(_artifact) = build_rtld() else {
        return;
    };
    let interp = rtld_interp_path();
    assert!(interp.exists(), "missing {}", interp.display());

    let dir = test_work_dir("cli-simple-c");
    let source = dir.join("cli.c");
    let program = dir.join("cli");
    fs::write(
        &source,
        br#"
#include <stdio.h>

int main(void) {
    puts("cli");
    return 0;
}
"#,
    )
    .unwrap();
    assert!(
        Command::new("cc")
            .arg(&source)
            .arg("-o")
            .arg(&program)
            .status()
            .expect("failed to compile rtld CLI test program")
            .success(),
        "failed to compile rtld CLI test program"
    );

    let verify = Command::new(&interp)
        .arg("--verify")
        .arg(&program)
        .output()
        .expect("failed to execute rtld --verify");
    assert!(
        verify.status.success(),
        "rtld --verify failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&verify.stdout),
        String::from_utf8_lossy(&verify.stderr)
    );

    let list = Command::new(&interp)
        .arg("--list")
        .arg(&program)
        .output()
        .expect("failed to execute rtld --list");
    assert!(
        list.status.success(),
        "rtld --list failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&list.stdout),
        String::from_utf8_lossy(&list.stderr)
    );
    assert!(
        list.stderr.is_empty(),
        "unexpected stderr:\n{}",
        String::from_utf8_lossy(&list.stderr)
    );
    let list = String::from_utf8(list.stdout).expect("list output must be utf-8");
    assert!(list.contains("libc.so.6"), "{list}");
    assert!(list.contains("ld-linux-x86-64.so.2"), "{list}");
}

#[test]
fn rtld_artifact_command_line_can_run_simple_c_program_directly() {
    if !has_command("cc") {
        eprintln!("skipping direct rtld CLI execution test because cc is unavailable");
        return;
    }

    let Some(_artifact) = build_rtld() else {
        return;
    };
    let interp = rtld_interp_path();
    assert!(interp.exists(), "missing {}", interp.display());

    let dir = test_work_dir("cli-direct-simple-c");
    let source = dir.join("direct.c");
    let program = dir.join("direct");
    fs::write(
        &source,
        br#"
#include <stdio.h>

int main(int argc, char **argv) {
    printf("direct:%d:%s\n", argc, argv[0]);
    return argc + 7;
}
"#,
    )
    .unwrap();
    assert!(
        Command::new("cc")
            .arg(&source)
            .arg("-o")
            .arg(&program)
            .status()
            .expect("failed to compile direct rtld CLI test program")
            .success(),
        "failed to compile direct rtld CLI test program"
    );

    let output = Command::new(&interp)
        .arg("--argv0")
        .arg("custom-argv0")
        .arg(&program)
        .arg("payload")
        .output()
        .expect("failed to execute program through rtld CLI");
    assert!(
        output.stderr.is_empty(),
        "unexpected stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "direct:2:custom-argv0\n"
    );
    assert_eq!(output.status.code(), Some(9));
}

#[test]
fn rtld_artifact_can_tail_jump_dependency_free_program() {
    if !has_command("cc") {
        eprintln!("skipping dependency-free PT_INTERP test because cc is unavailable");
        return;
    }

    let Some(_artifact) = build_rtld() else {
        return;
    };
    let interp = rtld_interp_path();
    assert!(interp.exists(), "missing {}", interp.display());

    let dir = test_work_dir("pt-interp-no-needed");
    let source = dir.join("exit42.S");
    let program = dir.join("exit42");
    fs::write(
        &source,
        br#"
    .section .text,"ax",@progbits
    .globl _start
    .type _start,@function
_start:
    movl $42, %edi
    movl $60, %eax
    syscall
    .size _start, . - _start
"#,
    )
    .unwrap();

    assert!(
        Command::new("cc")
            .arg("-nostdlib")
            .arg("-fPIE")
            .arg("-pie")
            .arg(format!("-Wl,--dynamic-linker={}", interp.display()))
            .arg(&source)
            .arg("-o")
            .arg(&program)
            .status()
            .expect("failed to compile dependency-free test program")
            .success(),
        "failed to compile dependency-free test program"
    );

    let dynamic = command_output("readelf", &["-d", program.to_str().unwrap()]);
    assert!(
        !dynamic.contains("(NEEDED)"),
        "test program must not need shared libraries\n{dynamic}"
    );

    let output = Command::new(&program)
        .output()
        .expect("failed to execute dependency-free patched program");
    assert_eq!(output.status.code(), Some(42));
}

#[test]
fn rtld_artifact_handles_main_relocations_with_full_loader() {
    if !has_command("cc") {
        eprintln!("skipping dependency-free relocation test because cc is unavailable");
        return;
    }

    let Some(_artifact) = build_rtld() else {
        return;
    };
    let interp = rtld_interp_path();
    assert!(interp.exists(), "missing {}", interp.display());

    let dir = test_work_dir("pt-interp-relative-reloc");
    let source = dir.join("relative.S");
    let program = dir.join("relative");
    fs::write(
        &source,
        br#"
    .section .data,"aw",@progbits
value:
    .quad 42
anchor:
    .quad value

    .section .text,"ax",@progbits
    .globl _start
    .type _start,@function
_start:
    movq anchor(%rip), %rax
    movq (%rax), %rdi
    movl $60, %eax
    syscall
    .size _start, . - _start
"#,
    )
    .unwrap();

    assert!(
        Command::new("cc")
            .arg("-nostdlib")
            .arg("-fPIE")
            .arg("-pie")
            .arg(format!("-Wl,--dynamic-linker={}", interp.display()))
            .arg(&source)
            .arg("-o")
            .arg(&program)
            .status()
            .expect("failed to compile dependency-free relocation test program")
            .success(),
        "failed to compile dependency-free relocation test program"
    );

    let dynamic = command_output("readelf", &["-d", program.to_str().unwrap()]);
    assert!(
        !dynamic.contains("(NEEDED)"),
        "test program must not need shared libraries\n{dynamic}"
    );
    let relocations = command_output("readelf", &["-r", program.to_str().unwrap()]);
    assert!(
        relocations.contains("R_X86_64_RELATIVE"),
        "test program must exercise relative relocations\n{relocations}"
    );

    let output = Command::new(&program)
        .output()
        .expect("failed to execute dependency-free relocation test program");
    assert!(
        output.stderr.is_empty(),
        "unexpected stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.status.code(), Some(42));
}
