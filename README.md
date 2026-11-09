# dlopen-rs

[![Crates.io](https://img.shields.io/crates/v/dlopen-rs.svg)](https://crates.io/crates/dlopen-rs)
[![Docs.rs](https://docs.rs/dlopen-rs/badge.svg)](https://docs.rs/dlopen-rs/)
[![Build](https://github.com/weizhiao/rust-dynlinker/actions/workflows/rust.yml/badge.svg)](https://github.com/weizhiao/rust-dynlinker/actions/workflows/rust.yml)
![MSRV](https://img.shields.io/badge/rust-1.93.0%2B-blue.svg)
[![License](https://img.shields.io/crates/l/dlopen-rs.svg)](LICENSE)

English | [简体中文](README-zh_cn.md)

`dlopen-rs` is an ELF dynamic linker written in Rust. It loads shared libraries and resolves symbols.

Built on `elf_loader`, it supports `std` and `no_std` on Linux for x86_64, AArch64, and RISC-V 64-bit architectures. The repository also includes a C ABI adapter and an experimental standalone dynamic linker, `rtld`.

## Quick Start

Requires **Rust 1.93.0 or later**. Add the following to your `Cargo.toml`:

```toml
[dependencies]
dlopen-rs = "0.9.0"
```

Open a shared library with `ElfLibrary::dlopen`, then look up an exported symbol with `get`:

```rust
use dlopen_rs::{ElfLibrary, OpenFlags, Result};

fn main() -> Result<()> {
    let lib = ElfLibrary::dlopen(
        "./target/release/libexample.so",
        OpenFlags::RTLD_NOW,
    )?;
    let add = unsafe { lib.get::<fn(i32, i32) -> i32>("add")? };

    println!("add(1, 1) = {}", add(1, 1));
    Ok(())
}
```

This example calls a Rust function exported by the repository's example library. When using `get`, the caller must ensure that the symbol's type and calling convention are correct. For C functions, use the appropriate `extern "C" fn` type. The returned symbol borrows the library handle, which must remain alive while the symbol is in use.

From the repository root, build the example library and run the loading example:

```sh
cargo build --release -p example_dylib
cargo run --release --example dlopen
```

The example prints `add(1, 1) = 2` along with loading logs. These paths assume Cargo's default `target` directory.

See the [API documentation](https://docs.rs/dlopen-rs/) and repository examples for more:

| Example | Description |
| --- | --- |
| [dlopen](examples/dlopen.rs) | Load a shared library from a file and call a function |
| [dlopen_from_binary](examples/dlopen_from_binary.rs) | Load a shared library from ELF bytes in memory |
| [symbol_info](examples/symbol_info.rs) | Find the library and symbol associated with an address |

## Configuration

| Feature | Default | Description |
| --- | --- | --- |
| `std` | Yes | Use the standard library and initialize integration with the host dynamic linker |
| `use-syscall` | No | Use the Linux syscall backend for `no_std` environments |
| `version` | No | Enable ELF symbol version queries, such as `ElfLibrary::get_version` |

`std` and `use-syscall` cannot be enabled together. For `no_std` with the syscall backend:

```toml
[dependencies]
dlopen-rs = { version = "0.9.0", default-features = false, features = ["use-syscall"] }
```

The `no_std` configuration still uses `alloc`; the final program must provide an allocator.

## C ABI and LD_PRELOAD

`dlopen_rs::api` provides C ABI entry points including `dlopen`, `dlsym`, `dlclose`, `dlerror`, `dladdr`, and `dl_iterate_phdr`.

The [`cdylib`](cdylib/) crate exports these interfaces as `libdlopen.so` for experiments with `LD_PRELOAD`:

```sh
cargo build --release -p cdylib
```

The default output is `target/release/libdlopen.so`. This adapter is incomplete: for example, `dlinfo` in `cdylib` is not implemented, and `dlerror` is a placeholder. See the [preload example](examples/preload.rs) for usage.

## Standalone Dynamic Linker rtld (Experimental)

The repository also provides an experimental standalone dynamic linker, `rtld`, currently targeting x86_64 Linux. It is not yet fully compatible with glibc `ld.so`. Build it with `cargo +nightly build-rtld`; see the [rtld README](rtld/README.md) for details.

## Contributing

[Issues](https://github.com/weizhiao/rust-dynlinker/issues) and pull requests are welcome. When reporting a loading problem, include your operating system, CPU architecture, Rust version, enabled features, and minimal steps to reproduce it.

For debugging issues involving GDB, `r_debug`, or `link_map`, see the [GDB troubleshooting guide](TroubleshootingGdb.md).

## License

Licensed under the [Apache License 2.0](LICENSE).
