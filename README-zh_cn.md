# dlopen-rs

[![Crates.io](https://img.shields.io/crates/v/dlopen-rs.svg)](https://crates.io/crates/dlopen-rs)
[![Docs.rs](https://docs.rs/dlopen-rs/badge.svg)](https://docs.rs/dlopen-rs/)
[![Build](https://github.com/weizhiao/rust-dynlinker/actions/workflows/rust.yml/badge.svg)](https://github.com/weizhiao/rust-dynlinker/actions/workflows/rust.yml)
![MSRV](https://img.shields.io/badge/rust-1.93.0%2B-blue.svg)
[![License](https://img.shields.io/crates/l/dlopen-rs.svg)](LICENSE)

[English](README.md) | 简体中文

`dlopen-rs` 是一个用 Rust 实现的 ELF 动态链接器，支持加载共享库和查询符号。

项目基于 `elf_loader`，支持 `std` 和 `no_std`，面向 Linux 的 x86_64、AArch64 和 RISC-V 64 位架构。仓库还包含 C ABI 适配库和实验性的独立动态链接器 `rtld`。

## 快速开始

需要 **Rust 1.93.0 或更新版本**。在 `Cargo.toml` 中添加：

```toml
[dependencies]
dlopen-rs = "0.8.0"
```

使用 `ElfLibrary::dlopen` 打开动态库，再通过 `get` 查找导出的符号：

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

这里使用的是仓库中示例库导出的 Rust 函数。`get` 要求调用方保证符号的类型和调用约定正确；如果加载的是 C 函数，应使用对应的 `extern "C" fn` 类型。返回的符号借用库句柄，使用期间需要保留该句柄。

在仓库根目录运行下面的命令，即可构建示例库并体验加载流程：

```sh
cargo build --release -p example_dylib
cargo run --release --example dlopen
```

示例会输出 `add(1, 1) = 2`，同时打印加载日志。上面的路径使用 Cargo 默认的 `target` 目录。

更多用法见 [API 文档](https://docs.rs/dlopen-rs/) 和仓库示例：

| 示例 | 内容 |
| --- | --- |
| [dlopen](examples/dlopen.rs) | 从文件加载动态库并调用函数 |
| [dlopen_from_binary](examples/dlopen_from_binary.rs) | 从内存中的 ELF 字节加载动态库 |
| [symbol_info](examples/symbol_info.rs) | 查询地址对应的动态库与符号信息 |

## 配置

| Feature | 默认启用 | 作用 |
| --- | --- | --- |
| `std` | 是 | 使用标准库，并初始化与宿主动态链接器的集成 |
| `use-syscall` | 否 | 使用 Linux 系统调用后端，适用于 `no_std` 场景 |
| `version` | 否 | 启用 ELF 符号版本查询，如 `ElfLibrary::get_version` |

`std` 与 `use-syscall` 不能同时启用。使用 `no_std` 和系统调用后端时，配置为：

```toml
[dependencies]
dlopen-rs = { version = "0.8.0", default-features = false, features = ["use-syscall"] }
```

`no_std` 模式仍依赖 `alloc`，最终程序需要提供内存分配器。

## C ABI 与 LD_PRELOAD

`dlopen_rs::api` 提供 `dlopen`、`dlsym`、`dlclose`、`dlerror`、`dladdr` 和 `dl_iterate_phdr` 等 C ABI 入口。

仓库中的 [`cdylib`](cdylib/) 将相关接口导出为 `libdlopen.so`，用于 `LD_PRELOAD` 适配实验：

```sh
cargo build --release -p cdylib
```

默认产物为 `target/release/libdlopen.so`。这一适配层仍不完整，例如 `cdylib` 中的 `dlinfo` 尚未实现，`dlerror` 仍是占位实现。使用方式可参考 [preload 示例](examples/preload.rs)。

## 独立动态链接器 rtld（实验性）

仓库还提供实验性的独立动态链接器 `rtld`，目前面向 x86_64 Linux，尚未完整兼容 glibc `ld.so`。使用 nightly 工具链执行 `cargo +nightly build-rtld` 构建，详细说明见 [rtld README](rtld/README-zh_cn.md)。

## 参与贡献

欢迎通过 [Issue](https://github.com/weizhiao/rust-dynlinker/issues) 反馈问题，或提交 Pull Request。报告加载问题时，请附上操作系统、CPU 架构、Rust 版本、启用的 feature 和最小复现步骤。

涉及 GDB、`r_debug` 或 `link_map` 的调试问题，可参考 [GDB 排查说明](TroubleshootingGdb.md)。

## 许可证

本项目采用 [Apache License 2.0](LICENSE)。
