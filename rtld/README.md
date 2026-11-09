# rtld

English | [简体中文](README-zh_cn.md)

`rtld` is an experimental ELF program interpreter provided by dlopen-rs. It currently targets **x86_64 Linux** and implements part of the startup process and interfaces of glibc's `ld-linux-x86-64.so.2`. Full compatibility with glibc `ld.so` is still in progress.

## Build

A nightly toolchain and `rust-src` are required. Run from the repository root:

```sh
rustup toolchain install nightly --component rust-src
cargo +nightly build-rtld
```

The `build-rtld` alias is defined in [`.cargo/config.toml`](../.cargo/config.toml). It builds for `x86_64-unknown-linux-none` using `-Z build-std=core,alloc,compiler_builtins`.

The default outputs are:

```text
target/x86_64-unknown-linux-none/release/librtld.so
target/x86_64-unknown-linux-none/release/ld-linux-x86-64.so.2
```

`ld-linux-x86-64.so.2` is a symbolic link to `librtld.so`. If `CARGO_TARGET_DIR` is set, the outputs are written under that directory instead.

## Usage

From the repository root, view the command-line help:

```sh
./target/x86_64-unknown-linux-none/release/ld-linux-x86-64.so.2 --help
```

You can also specify a program to run, followed by its arguments:

```sh
./target/x86_64-unknown-linux-none/release/ld-linux-x86-64.so.2 /path/to/program
```

Some glibc command-line options are currently parsed without implementing their behavior. See the help output for details.

[Back to the project README](../README.md)
