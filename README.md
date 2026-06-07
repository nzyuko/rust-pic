# rust-pic

A small Windows Rust project for the blog post:

https://zer0.art/2026/05/28/writing-pic-in-rust/

This repo shows the difference between a normal Rust `.exe` and a PIC-style build.

A normal executable gets help from the Windows loader. Shellcode is different. It is just bytes in memory, so it has to find what it needs by itself.

The code keeps the important parts in one place: the custom entry point, the `no_std` build, the PEB walk, export lookup, indirect syscall demo, and payload extraction.

## build

Normal build:

```powershell
cargo build --release
```

PIC build:

```powershell
cargo build --release --features pic
```

Extract the payload:

```powershell
python tools\validate_pic.py target\release\pic_example.exe -o payload.bin
```

## test

Run the extracted payload with the local loader:

```powershell
cargo run --example loader -- payload.bin
```

The loader is only a small test harness. It allocates memory, copies the payload, and calls it so the build can be checked locally.

Read the walkthrough for the full explanation:

https://zer0.art/2026/05/28/writing-pic-in-rust/
