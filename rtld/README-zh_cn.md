# rtld

[English](README.md) | 简体中文

`rtld` 是 dlopen-rs 提供的实验性 ELF 程序解释器，目前面向 **x86_64 Linux**，正在实现 glibc `ld-linux-x86-64.so.2` 的部分接口和启动流程，尚未完整兼容 glibc `ld.so`。

## 构建

需要 nightly 工具链及 `rust-src`。在仓库根目录执行：

```sh
rustup toolchain install nightly --component rust-src
cargo +nightly build-rtld
```

`build-rtld` 别名定义在 [`.cargo/config.toml`](../.cargo/config.toml) 中，使用 `x86_64-unknown-linux-none` 目标和 `-Z build-std=core,alloc,compiler_builtins` 构建。

默认产物位于：

```text
target/x86_64-unknown-linux-none/release/librtld.so
target/x86_64-unknown-linux-none/release/ld-linux-x86-64.so.2
```

其中 `ld-linux-x86-64.so.2` 是指向 `librtld.so` 的符号链接。设置 `CARGO_TARGET_DIR` 后，产物会写入对应的目标目录。

## 使用

在仓库根目录查看命令行帮助：

```sh
./target/x86_64-unknown-linux-none/release/ld-linux-x86-64.so.2 --help
```

也可以直接指定要运行的程序，并在其后传入参数：

```sh
./target/x86_64-unknown-linux-none/release/ld-linux-x86-64.so.2 /path/to/program
```

部分 glibc 命令行选项目前仅被解析，尚未实现对应功能，具体以帮助信息为准。

[返回项目介绍](../README-zh_cn.md)
