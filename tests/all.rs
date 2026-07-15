mod support;

use dlopen_rs::{ElfLibrary, OpenFlags};
use std::env::consts;
use std::path::PathBuf;
use std::sync::{
    Arc, Barrier, OnceLock,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

const TARGET_DIR: Option<&'static str> = option_env!("CARGO_TARGET_DIR");
static TARGET_TRIPLE: OnceLock<String> = OnceLock::new();

fn lib_path(file_name: &str) -> String {
    let path: PathBuf = TARGET_DIR.unwrap_or("target").into();
    path.join(TARGET_TRIPLE.get().unwrap())
        .join("release")
        .join(file_name)
        .to_str()
        .unwrap()
        .to_string()
}

const PACKAGE_NAME: [&str; 2] = ["example_dylib", "promotion_dylib"];

fn compile() {
    static ONCE: ::std::sync::Once = ::std::sync::Once::new();
    ONCE.call_once(|| {
        unsafe { std::env::set_var("RUST_LOG", "trace") };
        env_logger::init();
        let arch = consts::ARCH;
        if arch.contains("x86_64") {
            TARGET_TRIPLE
                .set("x86_64-unknown-linux-gnu".to_string())
                .unwrap();
        } else if arch.contains("riscv64") {
            TARGET_TRIPLE
                .set("riscv64gc-unknown-linux-gnu".to_string())
                .unwrap();
        } else if arch.contains("aarch64") {
            TARGET_TRIPLE
                .set("aarch64-unknown-linux-gnu".to_string())
                .unwrap();
        } else if arch.contains("loongarch64") {
            TARGET_TRIPLE
                .set("loongarch64-unknown-linux-musl".to_string())
                .unwrap();
        } else {
            unimplemented!()
        }

        for name in PACKAGE_NAME {
            let mut cmd = ::std::process::Command::new("cargo");
            cmd.arg("build")
                .arg("-r")
                .arg("-p")
                .arg(name)
                .env("CARGO_PROFILE_RELEASE_PANIC", "unwind")
                .arg("--target")
                .arg(TARGET_TRIPLE.get().unwrap().as_str());
            support::apply_local_relink_patch(&mut cmd);
            assert!(
                cmd.status()
                    .expect("could not compile the test helpers!")
                    .success()
            );
        }

        let libexample = lib_path("libexample.so");
        let _ = std::fs::copy(&libexample, lib_path("libnodelete.so"));
        let _ = std::fs::copy(&libexample, lib_path("libexample_noload.so"));
        let _ = std::fs::copy(&libexample, lib_path("libunload_handles.so"));
        let _ = std::fs::copy(&libexample, lib_path("libunload_clone.so"));
        let _ = std::fs::copy(&libexample, lib_path("libunload_global.so"));
        let _ = std::fs::copy(&libexample, lib_path("libaddress_lease.so"));
        let _ = std::fs::copy(&libexample, lib_path("libthread_dtor.so"));
        let _ = std::fs::copy(&libexample, lib_path("libmulti_open.so"));
        let _ = std::fs::copy(&libexample, lib_path("libnested_outer.so"));
    });
}

#[test]
fn dlopen() {
    compile();
    let path = lib_path("libexample.so");
    assert!(ElfLibrary::dlopen(path, OpenFlags::RTLD_NOW).is_ok());
}

#[test]
fn dl_iterate_phdr() {
    compile();
    let path = lib_path("libexample.so");
    let _lib = ElfLibrary::dlopen(path, OpenFlags::RTLD_NOW).unwrap();
    let mut reentered = false;
    ElfLibrary::dl_iterate_phdr(|info| {
        println!("iterate dynamic library: {}", info.name());
        if !reentered {
            let _nested = ElfLibrary::dlopen(lib_path("libexample.so"), OpenFlags::RTLD_NOLOAD)?;
            reentered = true;
        }
        Ok(())
    })
    .unwrap();
    assert!(reentered);
}

#[test]
fn panic() {
    compile();
    let path = lib_path("libexample.so");
    let lib = ElfLibrary::dlopen(path, OpenFlags::RTLD_NOW).unwrap();
    let panic = unsafe { lib.get::<fn()>("panic").unwrap() };
    panic();
}

#[test]
fn rtld_noload() {
    compile();
    let path = lib_path("libexample_noload.so");

    // Should fail if not loaded
    assert!(ElfLibrary::dlopen(&path, OpenFlags::RTLD_NOLOAD).is_err());

    // Load it
    let _lib = ElfLibrary::dlopen(&path, OpenFlags::RTLD_LOCAL).unwrap();

    // Should succeed now
    assert!(ElfLibrary::dlopen(&path, OpenFlags::RTLD_NOLOAD).is_ok());

    // Should succeed with promotion
    let lib_global =
        ElfLibrary::dlopen(&path, OpenFlags::RTLD_NOLOAD | OpenFlags::RTLD_GLOBAL).unwrap();
    assert!(lib_global.flags().contains(OpenFlags::RTLD_GLOBAL));
}

#[test]
fn unloads_after_last_dlopen_handle() {
    compile();
    let path = lib_path("libunload_handles.so");
    let first = ElfLibrary::dlopen(&path, OpenFlags::RTLD_NOW).unwrap();
    let second = ElfLibrary::dlopen(&path, OpenFlags::RTLD_NOW).unwrap();

    drop(first);
    let probe = ElfLibrary::dlopen(&path, OpenFlags::RTLD_NOLOAD)
        .expect("the second handle must keep the object loaded");
    drop(probe);
    drop(second);

    assert!(ElfLibrary::dlopen(&path, OpenFlags::RTLD_NOLOAD).is_err());
}

#[test]
fn concurrent_first_open_shares_one_mapping() {
    compile();
    const THREADS: usize = 8;
    let path = lib_path("libmulti_open.so");
    let start = Arc::new(Barrier::new(THREADS));
    let opened = Arc::new(Barrier::new(THREADS + 1));
    let threads = (0..THREADS)
        .map(|_| {
            let path = path.clone();
            let start = start.clone();
            let opened = opened.clone();
            std::thread::spawn(move || {
                start.wait();
                let lib = ElfLibrary::dlopen(&path, OpenFlags::RTLD_NOW).unwrap();
                let base = lib.base();
                opened.wait();
                base
            })
        })
        .collect::<Vec<_>>();

    opened.wait();
    let bases = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect::<Vec<_>>();
    assert!(bases.iter().all(|base| *base == bases[0]));
    assert!(ElfLibrary::dlopen(&path, OpenFlags::RTLD_NOLOAD).is_err());
}

#[test]
fn constructor_can_recursively_dlopen() {
    compile();
    let outer = ElfLibrary::dlopen(lib_path("libnested_outer.so"), OpenFlags::RTLD_NOW).unwrap();
    let nested_loaded = unsafe {
        outer
            .get::<extern "C" fn() -> bool>("nested_init_loaded")
            .unwrap()
    };
    assert!(
        nested_loaded(),
        "constructor must see its committed module and recursively load the target"
    );

    let close_nested = unsafe {
        outer
            .get::<unsafe extern "C" fn()>("close_nested_init_handle")
            .unwrap()
    };
    unsafe { close_nested() };
}

#[test]
fn cloned_handle_shares_one_dlopen_lease() {
    compile();
    let path = lib_path("libunload_clone.so");
    let handle = ElfLibrary::dlopen(&path, OpenFlags::RTLD_NOW).unwrap();
    let cloned = handle.clone();

    drop(handle);
    let probe = ElfLibrary::dlopen(&path, OpenFlags::RTLD_NOLOAD)
        .expect("a Rust clone must retain its shared dlopen lease");
    drop(probe);
    drop(cloned);

    assert!(ElfLibrary::dlopen(&path, OpenFlags::RTLD_NOLOAD).is_err());
}

#[test]
fn rtld_global_does_not_prevent_unloading() {
    compile();
    let path = lib_path("libunload_global.so");
    let handle = ElfLibrary::dlopen(&path, OpenFlags::RTLD_NOW | OpenFlags::RTLD_GLOBAL).unwrap();
    drop(handle);

    assert!(ElfLibrary::dlopen(&path, OpenFlags::RTLD_NOLOAD).is_err());
}

#[test]
fn promotion() {
    compile();
    let path = lib_path("libpromotion.so");

    // 1. Load with RTLD_LOCAL
    let lib_local = ElfLibrary::dlopen(&path, OpenFlags::RTLD_LAZY).unwrap();
    assert!(!lib_local.flags().contains(OpenFlags::RTLD_GLOBAL));

    // Symbol should NOT be in global scope
    assert!(dlopen_rs::dlsym_default::<fn(i32, i32) -> i32>("promotion_add").is_err());

    // 2. Promote to RTLD_GLOBAL
    let lib_promoted =
        ElfLibrary::dlopen(&path, OpenFlags::RTLD_LAZY | OpenFlags::RTLD_GLOBAL).unwrap();
    assert!(lib_promoted.flags().contains(OpenFlags::RTLD_GLOBAL));

    // Symbol SHOULD be in global scope now
    let add_sym = dlopen_rs::dlsym_default::<fn(i32, i32) -> i32>("promotion_add")
        .expect("Symbol should be available after promotion");
    assert_eq!(add_sym(1, 2), 3);
}

#[test]
fn soname_alias() {
    compile();
    let path = lib_path("libpromotion.so");

    let lib = ElfLibrary::dlopen(&path, OpenFlags::RTLD_NOW).unwrap();
    assert_eq!(lib.name(), "libpromotion_soname.so.1");

    let by_soname = ElfLibrary::dlopen(
        "libpromotion_soname.so.1",
        OpenFlags::RTLD_NOW | OpenFlags::RTLD_NOLOAD,
    )
    .expect("SONAME should be an alias for the already loaded object");
    assert_eq!(by_soname.name(), lib.name());
}

#[test]
fn nodelete() {
    compile();
    let path = lib_path("libnodelete.so");

    let lib = ElfLibrary::dlopen(&path, OpenFlags::RTLD_LAZY).unwrap();
    assert!(!lib.flags().contains(OpenFlags::RTLD_NODELETE));

    // Promote to RTLD_NODELETE
    let lib_nodelete =
        ElfLibrary::dlopen(&path, OpenFlags::RTLD_LAZY | OpenFlags::RTLD_NODELETE).unwrap();
    assert!(lib_nodelete.flags().contains(OpenFlags::RTLD_NODELETE));

    drop(lib);
    drop(lib_nodelete);
    assert!(ElfLibrary::dlopen(&path, OpenFlags::RTLD_NOLOAD).is_ok());
}

#[test]
fn dladdr() {
    compile();
    let path = lib_path("libaddress_lease.so");
    let lib = ElfLibrary::dlopen(path, OpenFlags::RTLD_NOW).unwrap();
    let print = unsafe { lib.get::<fn(&str)>("print").unwrap() }.into_raw() as usize;
    let find = ElfLibrary::dladdr(print).unwrap();
    assert!(find.dylib().name() == lib.name());

    drop(lib);
    let probe = ElfLibrary::dlopen("libaddress_lease.so", OpenFlags::RTLD_NOLOAD)
        .expect("DlInfo must retain its library lease");
    drop(probe);
    drop(find);
    assert!(ElfLibrary::dlopen("libaddress_lease.so", OpenFlags::RTLD_NOLOAD).is_err());
}

#[test]
fn thread_local() {
    compile();
    let path = lib_path("libexample.so");
    let lib = ElfLibrary::dlopen(path, OpenFlags::RTLD_NOW).unwrap();
    let thread_local = unsafe { lib.get::<fn()>("thread_local").unwrap() };
    thread_local();
}

#[test]
fn thread_destructor_keeps_library_loaded() {
    compile();
    let path = lib_path("libthread_dtor.so");
    let lib = ElfLibrary::dlopen(&path, OpenFlags::RTLD_NOW).unwrap();
    let start = unsafe {
        lib.get::<unsafe extern "C" fn(*const AtomicUsize)>("start_tls_destructor_thread")
            .unwrap()
    };
    let state = AtomicUsize::new(0);

    unsafe { start(&state) };
    let deadline = Instant::now() + Duration::from_secs(5);
    while state.load(Ordering::Acquire) != 1 {
        assert!(Instant::now() < deadline, "TLS worker did not start");
        std::thread::yield_now();
    }

    drop(lib);
    let probe = ElfLibrary::dlopen(&path, OpenFlags::RTLD_NOLOAD)
        .expect("pending TLS destructor must keep its library loaded");
    drop(probe);

    state.store(2, Ordering::Release);
    while state.load(Ordering::Acquire) != 3 {
        assert!(
            Instant::now() < deadline,
            "TLS destructor did not run at thread exit"
        );
        std::thread::yield_now();
    }

    loop {
        match ElfLibrary::dlopen(&path, OpenFlags::RTLD_NOLOAD) {
            Err(_) => break,
            Ok(probe) => drop(probe),
        }
        assert!(
            Instant::now() < deadline,
            "library remained loaded after its TLS destructor"
        );
        std::thread::yield_now();
    }
}

#[test]
fn linker_script() {
    compile();
    let path = lib_path("libexample.so");
    let lib_dir = PathBuf::from(&path).parent().unwrap().to_path_buf();
    let script_path = lib_dir.join("test_script.so");
    std::fs::write(&script_path, format!("GROUP ( {path} )")).unwrap();

    let lib = ElfLibrary::dlopen(script_path.to_str().unwrap(), OpenFlags::RTLD_NOW).unwrap();
    assert!(lib.name().contains("libexample.so"));
}

#[test]
fn linker_script_as_needed() {
    compile();
    let path = lib_path("libexample.so");
    let lib_dir = PathBuf::from(&path).parent().unwrap().to_path_buf();
    let script_path = lib_dir.join("test_script_as_needed.so");
    std::fs::write(&script_path, format!("GROUP ( AS_NEEDED ( {path} ) )")).unwrap();

    let lib = ElfLibrary::dlopen(script_path.to_str().unwrap(), OpenFlags::RTLD_NOW).unwrap();
    assert!(lib.name().contains("libexample.so"));
}
